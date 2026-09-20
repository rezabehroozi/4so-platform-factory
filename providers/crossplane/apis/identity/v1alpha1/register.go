package v1alpha1

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

const (
	Group   = "identity.platform.4so.io"
	Version = "v1alpha1"
)

var (
	SchemeGroupVersion          = schema.GroupVersion{Group: Group, Version: Version}
	SchemeBuilder               = &scheme.Builder{GroupVersion: SchemeGroupVersion}
	SAMLBrokerKind              = reflect.TypeOf(SAMLBroker{}).Name()
	SAMLBrokerGroupKind         = schema.GroupKind{Group: Group, Kind: SAMLBrokerKind}.String()
	SAMLBrokerGroupVersionKind  = SchemeGroupVersion.WithKind(SAMLBrokerKind)
)

func init() { SchemeBuilder.Register(&SAMLBroker{}, &SAMLBrokerList{}) }
