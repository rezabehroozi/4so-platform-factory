package controlplane

func managedResourceOperationDigest(op ManagedResourceOperation) string {
	copy := op
	copy.OperationDigest = ""
	return digestApplicationPlatformMaterial(copy)
}
