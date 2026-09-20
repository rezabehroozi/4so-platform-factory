module platform.4so.io/factory/providers/crossplane

go 1.25.11

require (
	github.com/crossplane/crossplane-runtime/v2 v2.3.3
	github.com/crossplane/crossplane/apis/v2 v2.3.4
	k8s.io/api v0.35.1
	k8s.io/apimachinery v0.35.1
	k8s.io/client-go v0.35.1
	sigs.k8s.io/controller-runtime v0.23.1
	platform.4so.io/factory v0.0.0
)

replace platform.4so.io/factory => ../..
