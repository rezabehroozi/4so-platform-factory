package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type SecretKeyReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ProviderConfigSpec struct {
	Endpoint       string             `json:"endpoint"`
	TokenSecretRef SecretKeyReference `json:"tokenSecretRef"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,provider,4so}
// +kubebuilder:subresource:status
type ProviderConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ProviderConfigSpec `json:"spec"`
}

// +kubebuilder:object:root=true
type ProviderConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProviderConfig `json:"items"`
}

func (in *ProviderConfig) DeepCopyInto(out *ProviderConfig) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}
func (in *ProviderConfig) DeepCopy() *ProviderConfig {
	if in == nil {
		return nil
	}
	out := new(ProviderConfig)
	in.DeepCopyInto(out)
	return out
}
func (in *ProviderConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
func (in *ProviderConfigList) DeepCopyInto(out *ProviderConfigList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ProviderConfig, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *ProviderConfigList) DeepCopy() *ProviderConfigList {
	if in == nil {
		return nil
	}
	out := new(ProviderConfigList)
	in.DeepCopyInto(out)
	return out
}
func (in *ProviderConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
