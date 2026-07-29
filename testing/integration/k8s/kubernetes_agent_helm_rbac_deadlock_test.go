// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

// Regression test for https://github.com/elastic/elastic-agent/issues/15666.
//
// When the kubernetes integration runs with insufficient RBAC (some state_*
// informers cannot sync due to 403), a subsequent config reload deadlocks in
// the beats kubernetes enricher: enricher.Start() holds resourceWatchers.lock
// while blocked inside WaitForCacheSync(), and enricher.Stop() can never
// acquire that lock to cancel the watcher context.  The component stays in
// STOPPING forever.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent-libs/kibana"
	aclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// TestKubernetesAgentHelmRBACDeadlock deploys elastic-agent via Helm in
// Fleet-managed mode with a stripped ClusterRole (state_* resources removed),
// installs the kubernetes integration, then removes it to trigger a config
// reload.  Before the fix the component would stay in STOPPING indefinitely;
// after the fix it must leave STOPPING within the assertion timeout.
func TestKubernetesAgentHelmRBACDeadlock(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
	kCtx := k8sGetContext(t, info)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable kubernetes nodes found")

	testNamespace := kCtx.getNamespace(t)

	// ClusterRole is cluster-scoped; embed the namespace to keep names unique
	// across parallel runs.
	restrictedRoleName := "test-restricted-k8s-" + testNamespace

	// packagePolicyID is populated by k8sStepInstallKubernetesIntegration and
	// read by k8sStepDeleteFleetPackage.
	var packagePolicyID string

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepCreateRestrictedK8sClusterRole(restrictedRoleName),
		k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
			"agent": map[string]any{
				"image": map[string]any{
					"repository": kCtx.agentImageRepo,
					"tag":        kCtx.agentImageTag,
					"pullPolicy": "Never",
				},
				"fleet": map[string]any{
					"enabled": true,
					"url":     kCtx.enrollParams.FleetURL,
					"token":   kCtx.enrollParams.EnrollmentToken,
					"preset":  "perNode",
				},
				"presets": map[string]any{
					"perNode": map[string]any{
						"clusterRole": map[string]any{
							// Disable chart-managed ClusterRole creation and
							// bind to our restricted role instead.
							"create": false,
							"name":   restrictedRoleName,
						},
					},
				},
			},
		}),
		k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil),
		k8sStepInstallKubernetesIntegration(info.KibanaClient, kCtx.enrollParams.PolicyID, &packagePolicyID),
		// Wait until kubernetes/metrics-default appears in agent status
		// (it may be degraded due to 403s, but it should be running).
		k8sStepWaitForComponentPresent("name=agent-pernode-helm-agent", schedulableNodeCount, "agent",
			"kubernetes/metrics-default", 3*time.Minute),
		// Removing the integration triggers elastic-otel-collector Shutdown().
		// With the bug the component stays in STOPPING forever; with the fix it
		// must leave STOPPING within the assertion window.
		k8sStepDeleteFleetPackage(info.KibanaClient, &packagePolicyID),
		k8sStepAssertComponentNotStuck("name=agent-pernode-helm-agent", schedulableNodeCount, "agent",
			"kubernetes/metrics-default", 2*time.Minute),
	}

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
		if t.Failed() {
			return
		}
	}
}

// k8sStepCreateRestrictedK8sClusterRole creates a ClusterRole that grants only
// the minimum permissions the kubernetes integration needs for pod/node/event
// collection, deliberately omitting the state_* resources (services,
// deployments, daemonsets, statefulsets, jobs, cronjobs, persistentvolumes,
// persistentvolumeclaims, storageclasses).  This reproduces the RBAC
// misconfiguration from https://github.com/elastic/elastic-agent/issues/15666.
func k8sStepCreateRestrictedK8sClusterRole(roleName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: roleName,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"namespaces",
						"pods",
						"nodes",
						"nodes/metrics",
						"nodes/proxy",
						"nodes/stats",
						"events",
					},
					Verbs: []string{"get", "watch", "list"},
				},
				{
					APIGroups: []string{"coordination.k8s.io"},
					Resources: []string{"leases"},
					Verbs:     []string{"get", "create", "update"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"replicasets"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					NonResourceURLs: []string{"/metrics", "/healthz", "/healthz/*", "/livez", "/livez/*", "/readyz", "/readyz/*"},
					Verbs:           []string{"get"},
				},
			},
		}

		t.Cleanup(func() {
			if err := k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: false}, cr); err != nil {
				t.Logf("failed to delete restricted ClusterRole %s: %v", roleName, err)
			}
		})

		require.NoError(t, k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: false}, cr),
			"failed to create restricted ClusterRole")
	}
}

// k8sStepInstallKubernetesIntegration installs the kubernetes Fleet integration
// into the given policy.  It resolves the latest available package version from
// the Fleet EPM API and stores the created package-policy ID into *policyIDOut
// so that a later step can delete it.
func k8sStepInstallKubernetesIntegration(kc *kibana.Client, agentPolicyID string, policyIDOut *string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		version, err := getFleetPackageVersion(ctx, kc, "kubernetes")
		require.NoError(t, err, "failed to resolve kubernetes package version")

		policyUUID := uuid.Must(uuid.NewV4()).String()
		resp, err := kc.InstallFleetPackage(ctx, kibana.PackagePolicyRequest{
			Name:      "kubernetes-" + policyUUID,
			Namespace: "default",
			PolicyID:  agentPolicyID,
			Package: kibana.PackagePolicyRequestPackage{
				Name:    "kubernetes",
				Version: version,
			},
			Inputs: []map[string]interface{}{},
		})
		require.NoError(t, err, "failed to install kubernetes Fleet package")
		*policyIDOut = resp.Item.ID
	}
}

// k8sStepDeleteFleetPackage deletes the package policy whose ID is stored in
// *policyID, triggering a config reload on enrolled agents.
func k8sStepDeleteFleetPackage(kc *kibana.Client, policyID *string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.NotEmpty(t, *policyID, "package policy ID must be set before deletion")
		_, err := kc.DeleteFleetPackage(ctx, *policyID)
		require.NoError(t, err, "failed to delete Fleet package policy %s", *policyID)
	}
}

// k8sStepWaitForComponentPresent polls elastic-agent status inside each pod
// matched by selector until the named component appears (in any state) or the
// timeout expires.
func k8sStepWaitForComponentPresent(
	agentPodLabelSelector string, expectedPodNumber int, containerName string,
	componentName string, timeout time.Duration,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		podList := listAgentPods(t, ctx, kCtx, namespace, agentPodLabelSelector, expectedPodNumber)

		for _, pod := range podList.Items {
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				status := execAgentStatus(ctx, kCtx, namespace, pod.Name, containerName)
				_, found := getAgentComponentState(status, componentName)
				assert.True(c, found, "component %s not yet present in pod %s", componentName, pod.Name)
			}, timeout, 2*time.Second,
				"component %s did not appear in pod %s within %s", componentName, pod.Name, timeout)
		}
	}
}

// k8sStepAssertComponentNotStuck asserts that the named component is no longer
// in STOPPING state within the timeout window.  This is the regression guard:
// before the fix the component would stay in STOPPING indefinitely.
func k8sStepAssertComponentNotStuck(
	agentPodLabelSelector string, expectedPodNumber int, containerName string,
	componentName string, timeout time.Duration,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		podList := listAgentPods(t, ctx, kCtx, namespace, agentPodLabelSelector, expectedPodNumber)

		for _, pod := range podList.Items {
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				status := execAgentStatus(ctx, kCtx, namespace, pod.Name, containerName)
				state, found := getAgentComponentState(status, componentName)
				// Accept both: component has stopped (not present) or is no
				// longer in STOPPING.
				if found {
					assert.NotEqual(c, int(aclient.Stopping), state,
						"component %s is still in STOPPING in pod %s", componentName, pod.Name)
				}
			}, timeout, 2*time.Second,
				"component %s is still stuck in STOPPING in pod %s after %s", componentName, pod.Name, timeout)
		}
	}
}

// getFleetPackageVersion queries the Fleet EPM API for the latest version of
// the named integration package.
func getFleetPackageVersion(ctx context.Context, kc *kibana.Client, packageName string) (string, error) {
	resp, err := kc.SendWithContext(ctx, http.MethodGet,
		"/api/fleet/epm/packages/"+packageName, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("querying EPM for %s: %w", packageName, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading EPM response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("EPM returned %d for %s: %s", resp.StatusCode, packageName, body)
	}

	var result struct {
		Item struct {
			Version string `json:"version"`
		} `json:"item"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing EPM response: %w", err)
	}
	if result.Item.Version == "" {
		return "", fmt.Errorf("EPM response for %s has no version field: %s", packageName, body)
	}
	return result.Item.Version, nil
}

// listAgentPods lists pods matching selector and fails if the count is
// unexpected.
func listAgentPods(
	t *testing.T, ctx context.Context, kCtx k8sContext,
	namespace, selector string, expected int,
) *corev1.PodList {
	t.Helper()
	podList := &corev1.PodList{}
	err := kCtx.client.Resources(namespace).List(ctx, podList, func(opt *metav1.ListOptions) {
		opt.LabelSelector = selector
	})
	require.NoError(t, err, "failed to list pods with selector %s", selector)
	require.Len(t, podList.Items, expected,
		"unexpected number of pods with selector %s", selector)
	return podList
}

// execAgentStatus runs `elastic-agent status --output=json` inside the
// container and returns the parsed output.  It tolerates exec errors (e.g.
// transient pod restart) by returning a zero-value status.
func execAgentStatus(
	ctx context.Context, kCtx k8sContext,
	namespace, podName, containerName string,
) atesting.AgentStatusOutput {
	var stdout, stderr bytes.Buffer
	execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_ = kCtx.client.Resources().ExecInPod(execCtx, namespace, podName, containerName,
		[]string{"elastic-agent", "status", "--output=json"}, &stdout, &stderr)

	var status atesting.AgentStatusOutput
	_ = json.Unmarshal(stdout.Bytes(), &status)
	return status
}
