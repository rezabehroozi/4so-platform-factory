package controlplane

func digestApplicationPromotionOperation(op ApplicationPromotionOperation) string {
	copy := op
	copy.OperationDigest = ""
	return digestApplicationPlatformMaterial(copy)
}
