package controlplane

import "time"

// OperatorAttentionItem is the bounded, cross-resource operator inbox item used
// by the Overview page. It intentionally carries only the fields required to
// identify, explain and route an urgent item; detailed resource payloads remain
// behind their owning APIs.
type OperatorAttentionItem struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	DisplayName string    `json:"displayName"`
	State       string    `json:"state"`
	Message     string    `json:"message"`
	Page        string    `json:"page"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
