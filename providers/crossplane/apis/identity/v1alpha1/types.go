package v1alpha1

import (
	resource "github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	_ resource.ModernManaged = &SAMLBroker{}
	_ resource.ManagedList   = &SAMLBrokerList{}
)

type SAMLBrokerParameters struct {
	OrganizationID          string `json:"organizationId"`
	Alias                   string `json:"alias"`
	DisplayName             string `json:"displayName"`
	EntityID                string `json:"entityId"`
	SingleSignOnServiceURL  string `json:"singleSignOnServiceUrl"`
	SingleLogoutServiceURL  string `json:"singleLogoutServiceUrl,omitempty"`
	SigningCertificate      string `json:"signingCertificate"`
	NameIDPolicyFormat      string `json:"nameIdPolicyFormat,omitempty"`
	WantAuthnRequestsSigned bool   `json:"wantAuthnRequestsSigned"`
	Enabled                 bool   `json:"enabled"`
}

type SAMLBrokerObservation struct {
	KeycloakAlias    string `json:"keycloakAlias,omitempty"`
	Revision         int64  `json:"revision,omitempty"`
	BrokerState      string `json:"brokerState,omitempty"`
	DesiredDigest    string `json:"desiredDigest,omitempty"`
	ObservedDigest   string `json:"observedDigest,omitempty"`
	RequestedBy      string `json:"requestedBy,omitempty"`
	LastError        string `json:"lastError,omitempty"`
	JobID            string `json:"jobId,omitempty"`
	JobState         string `json:"jobState,omitempty"`
	ApprovalRequired bool   `json:"approvalRequired,omitempty"`
}

type SAMLBrokerSpec struct {
	xpv2.ManagedResourceSpec `json:",inline"`
	ForProvider              SAMLBrokerParameters `json:"forProvider"`
}

type SAMLBrokerStatus struct {
	xpv2.ManagedResourceStatus `json:",inline"`
	AtProvider                 SAMLBrokerObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,4so}
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
type SAMLBroker struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SAMLBrokerSpec   `json:"spec"`
	Status            SAMLBrokerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SAMLBrokerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SAMLBroker `json:"items"`
}

func (mg *SAMLBroker) GetCondition(ct xpv2.ConditionType) xpv2.Condition {
	return mg.Status.GetCondition(ct)
}
func (mg *SAMLBroker) GetManagementPolicies() xpv2.ManagementPolicies {
	return mg.Spec.ManagementPolicies
}
func (mg *SAMLBroker) GetProviderConfigReference() *xpv2.ProviderConfigReference {
	return mg.Spec.ProviderConfigReference
}
func (mg *SAMLBroker) GetWriteConnectionSecretToReference() *xpv2.LocalSecretReference {
	return mg.Spec.WriteConnectionSecretToReference
}
func (mg *SAMLBroker) SetConditions(c ...xpv2.Condition) { mg.Status.SetConditions(c...) }
func (mg *SAMLBroker) SetManagementPolicies(p xpv2.ManagementPolicies) {
	mg.Spec.ManagementPolicies = p
}
func (mg *SAMLBroker) SetProviderConfigReference(r *xpv2.ProviderConfigReference) {
	mg.Spec.ProviderConfigReference = r
}
func (mg *SAMLBroker) SetWriteConnectionSecretToReference(r *xpv2.LocalSecretReference) {
	mg.Spec.WriteConnectionSecretToReference = r
}
func (l *SAMLBrokerList) GetItems() []resource.Managed {
	items := make([]resource.Managed, len(l.Items))
	for i := range l.Items {
		items[i] = &l.Items[i]
	}
	return items
}

func (in *SAMLBroker) DeepCopyInto(out *SAMLBroker) {
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.ManagedResourceSpec.DeepCopyInto(&out.Spec.ManagedResourceSpec)
	in.Status.ManagedResourceStatus.DeepCopyInto(&out.Status.ManagedResourceStatus)
}
func (in *SAMLBroker) DeepCopy() *SAMLBroker {
	if in == nil {
		return nil
	}
	out := new(SAMLBroker)
	in.DeepCopyInto(out)
	return out
}
func (in *SAMLBroker) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
func (in *SAMLBrokerList) DeepCopyInto(out *SAMLBrokerList) {
	*out = *in
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]SAMLBroker, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
func (in *SAMLBrokerList) DeepCopy() *SAMLBrokerList {
	if in == nil {
		return nil
	}
	out := new(SAMLBrokerList)
	in.DeepCopyInto(out)
	return out
}
func (in *SAMLBrokerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
