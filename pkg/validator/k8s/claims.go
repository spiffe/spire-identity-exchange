package k8s

// Claims holds Kubernetes service-account token specific fields used
// internally for typed access when generating selectors.
type Claims struct {
	Subject            string
	ClusterName        string
	Namespace          string
	ServiceAccountName string
	ServiceAccountUID  string
	PodName            string
	PodUID             string
	NodeName           string
	NodeUID            string
}

// claimsFromRaw extracts K8s claim fields from a raw claims map. It tolerates both
// modern projected service-account tokens (kubernetes.io.{namespace,serviceaccount,...})
// and legacy slash-delimited keys (kubernetes.io/serviceaccount/namespace).
func claimsFromRaw(raw map[string]interface{}) *Claims {
	c := &Claims{
		Subject: getString(raw, "sub"),
		// Injected by the validator from operator-configured clusterName, never
		// from the token itself.
		ClusterName: getString(raw, "k8s_cluster_name"),
	}

	// Modern projected token shape: kubernetes.io -> { namespace, serviceaccount: {name, uid}, pod: {...}, node: {...} }
	if k8sio, ok := raw["kubernetes.io"].(map[string]interface{}); ok {
		c.Namespace = getString(k8sio, "namespace")
		if sa, ok := k8sio["serviceaccount"].(map[string]interface{}); ok {
			c.ServiceAccountName = getString(sa, "name")
			c.ServiceAccountUID = getString(sa, "uid")
		}
		if pod, ok := k8sio["pod"].(map[string]interface{}); ok {
			c.PodName = getString(pod, "name")
			c.PodUID = getString(pod, "uid")
		}
		if node, ok := k8sio["node"].(map[string]interface{}); ok {
			c.NodeName = getString(node, "name")
			c.NodeUID = getString(node, "uid")
		}
	}

	// Legacy in-cluster SA token shape: keys are flat with embedded slashes.
	if c.Namespace == "" {
		c.Namespace = getString(raw, "kubernetes.io/serviceaccount/namespace")
	}
	if c.ServiceAccountName == "" {
		c.ServiceAccountName = getString(raw, "kubernetes.io/serviceaccount/service-account.name")
	}
	if c.ServiceAccountUID == "" {
		c.ServiceAccountUID = getString(raw, "kubernetes.io/serviceaccount/service-account.uid")
	}

	return c
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
