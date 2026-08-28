package controlplane

func resourceCreatedBefore(left, right ResourceMeta) bool {
	if left.CreatedAt.Equal(right.CreatedAt) {
		return left.ID < right.ID
	}
	return left.CreatedAt.Before(right.CreatedAt)
}

func resourceUpdatedBefore(left, right ResourceMeta) bool {
	if left.UpdatedAt.Equal(right.UpdatedAt) {
		return left.ID < right.ID
	}
	return left.UpdatedAt.Before(right.UpdatedAt)
}
