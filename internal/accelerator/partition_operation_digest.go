package accelerator

func digestPartitionOperation(op PartitionOperation) (string, error) {
	copy := op
	copy.OperationDigest = ""
	return digestValue(copy)
}
