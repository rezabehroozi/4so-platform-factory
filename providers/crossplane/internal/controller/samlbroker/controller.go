package samlbroker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	xpv2 "github.com/crossplane/crossplane/apis/v2/core/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	identityv1alpha1 "platform.4so.io/factory/providers/crossplane/apis/identity/v1alpha1"
	providerv1alpha1 "platform.4so.io/factory/providers/crossplane/apis/v1alpha1"
	factorysdk "platform.4so.io/factory/sdk/go"
)

const defaultProviderConfigName = "default"

type connector struct {
	kube       client.Client
	httpClient *http.Client
}

type external struct {
	client *factorysdk.Client
}

type samlBrokerAPI struct {
	ID                      string `json:"id"`
	Revision                int64  `json:"revision"`
	OrganizationID          string `json:"organizationId"`
	Alias                   string `json:"alias"`
	KeycloakAlias           string `json:"keycloakAlias"`
	DisplayName             string `json:"displayName"`
	EntityID                string `json:"entityId"`
	SingleSignOnServiceURL  string `json:"singleSignOnServiceUrl"`
	SingleLogoutServiceURL  string `json:"singleLogoutServiceUrl"`
	SigningCertificate      string `json:"signingCertificate"`
	NameIDPolicyFormat      string `json:"nameIdPolicyFormat"`
	WantAuthnRequestsSigned bool   `json:"wantAuthnRequestsSigned"`
	Enabled                 bool   `json:"enabled"`
	State                   string `json:"state"`
	DesiredDigest           string `json:"desiredDigest"`
	ObservedDigest          string `json:"observedDigest"`
	RequestedBy             string `json:"requestedBy"`
	LastError               string `json:"lastError"`
}

type identityAdminJobAPI struct {
	ID       string `json:"id"`
	BrokerID string `json:"brokerId"`
	State    string `json:"state"`
}

type samlMutationResponse struct {
	Broker samlBrokerAPI       `json:"broker"`
	Job    identityAdminJobAPI `json:"job"`
}

type samlBrokerRequest struct {
	identityv1alpha1.SAMLBrokerParameters
	IdempotencyKey string `json:"idempotencyKey"`
}

// Setup registers a namespaced Crossplane managed-resource controller. Product
// API remains the only lifecycle authority; the controller never self-approves,
// retries an ambiguous mutation, or accesses PostgreSQL/SSH directly.
func Setup(mgr ctrl.Manager) error {
	r := managed.NewReconciler(
		mgr,
		resource.ManagedKind(identityv1alpha1.SAMLBrokerGroupVersionKind),
		managed.WithTypedExternalConnector[*identityv1alpha1.SAMLBroker](&connector{
			kube:       mgr.GetClient(),
			httpClient: &http.Client{Timeout: 30 * time.Second},
		}),
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named("samlbroker.identity.platform.4so.io").
		For(&identityv1alpha1.SAMLBroker{}).
		Complete(r)
}

func providerReference(cr *identityv1alpha1.SAMLBroker) (string, error) {
	ref := cr.GetProviderConfigReference()
	if ref == nil {
		return defaultProviderConfigName, nil
	}
	kind := strings.TrimSpace(ref.Kind)
	if kind != "" && kind != "ProviderConfig" {
		return "", fmt.Errorf("unsupported providerConfigRef kind %q; use namespaced ProviderConfig", ref.Kind)
	}
	name := strings.TrimSpace(ref.Name)
	if name == "" {
		return "", fmt.Errorf("providerConfigRef name is required")
	}
	return name, nil
}

func (c *connector) Connect(ctx context.Context, cr *identityv1alpha1.SAMLBroker) (managed.TypedExternalClient[*identityv1alpha1.SAMLBroker], error) {
	name, err := providerReference(cr)
	if err != nil {
		return nil, err
	}
	pc := &providerv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: name}, pc); err != nil {
		return nil, fmt.Errorf("get ProviderConfig %s/%s: %w", cr.Namespace, name, err)
	}
	endpoint := strings.TrimSpace(pc.Spec.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("ProviderConfig %s/%s endpoint is required", cr.Namespace, name)
	}
	secretName := strings.TrimSpace(pc.Spec.TokenSecretRef.Name)
	secretKey := strings.TrimSpace(pc.Spec.TokenSecretRef.Key)
	if secretName == "" || secretKey == "" {
		return nil, fmt.Errorf("ProviderConfig %s/%s tokenSecretRef name and key are required", cr.Namespace, name)
	}
	secret := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{Namespace: cr.Namespace, Name: secretName}, secret); err != nil {
		return nil, fmt.Errorf("get Product API token secret %s/%s: %w", cr.Namespace, secretName, err)
	}
	token, ok := secret.Data[secretKey]
	if !ok || strings.TrimSpace(string(token)) == "" {
		return nil, fmt.Errorf("Product API token secret %s/%s has no non-empty %q key", cr.Namespace, secretName, secretKey)
	}
	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	api, err := factorysdk.NewClient(endpoint, httpClient)
	if err != nil {
		return nil, fmt.Errorf("configure Product API client: %w", err)
	}
	api.BearerToken = strings.TrimSpace(string(token))
	return &external{client: api}, nil
}

func route(method, path string) (factorysdk.Route, error) {
	return factorysdk.StableRoute(method, path)
}

func desired(cr *identityv1alpha1.SAMLBroker) identityv1alpha1.SAMLBrokerParameters {
	return cr.Spec.ForProvider
}

func lookupBroker(ctx context.Context, api *factorysdk.Client, organizationID, id string) (samlBrokerAPI, bool, error) {
	r, err := route(http.MethodGet, "/api/v1/identity/saml-brokers")
	if err != nil {
		return samlBrokerAPI{}, false, err
	}
	var brokers []samlBrokerAPI
	q := url.Values{"organizationId": []string{strings.TrimSpace(organizationID)}}
	if _, err := api.Do(ctx, r, nil, q, nil, nil, &brokers); err != nil {
		return samlBrokerAPI{}, false, err
	}
	for _, broker := range brokers {
		if broker.ID == id {
			return broker, broker.State != "DELETED", nil
		}
	}
	return samlBrokerAPI{}, false, nil
}

func sameDesired(want identityv1alpha1.SAMLBrokerParameters, got samlBrokerAPI) bool {
	return strings.TrimSpace(want.OrganizationID) == got.OrganizationID &&
		strings.TrimSpace(want.Alias) == got.Alias &&
		strings.TrimSpace(want.DisplayName) == got.DisplayName &&
		strings.TrimSpace(want.EntityID) == got.EntityID &&
		strings.TrimSpace(want.SingleSignOnServiceURL) == got.SingleSignOnServiceURL &&
		strings.TrimSpace(want.SingleLogoutServiceURL) == got.SingleLogoutServiceURL &&
		strings.TrimSpace(want.SigningCertificate) == got.SigningCertificate &&
		strings.TrimSpace(want.NameIDPolicyFormat) == got.NameIDPolicyFormat &&
		want.WantAuthnRequestsSigned == got.WantAuthnRequestsSigned &&
		want.Enabled == got.Enabled
}

func projectStatus(cr *identityv1alpha1.SAMLBroker, broker samlBrokerAPI, job identityAdminJobAPI) {
	cr.Status.AtProvider = identityv1alpha1.SAMLBrokerObservation{
		KeycloakAlias:    broker.KeycloakAlias,
		Revision:         broker.Revision,
		BrokerState:      broker.State,
		DesiredDigest:    broker.DesiredDigest,
		ObservedDigest:   broker.ObservedDigest,
		RequestedBy:      broker.RequestedBy,
		LastError:        broker.LastError,
		JobID:            job.ID,
		JobState:         job.State,
		ApprovalRequired: job.State == "AWAITING_APPROVAL" || broker.State == "PENDING_APPROVAL",
	}
}

func (e *external) Observe(ctx context.Context, cr *identityv1alpha1.SAMLBroker) (managed.ExternalObservation, error) {
	id := meta.GetExternalName(cr)
	if strings.TrimSpace(id) == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	broker, exists, err := lookupBroker(ctx, e.client, cr.Spec.ForProvider.OrganizationID, id)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if !exists {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	projectStatus(cr, broker, identityAdminJobAPI{})
	if broker.State == "ACTIVE" && broker.LastError == "" {
		cr.Status.SetConditions(xpv2.Available())
	}
	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  sameDesired(desired(cr), broker),
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func mutationKey(action, id string, revision int64, d any) (string, error) {
	return factorysdk.DeterministicMutationKey("crossplane-saml", action, id, revision, d)
}

func (e *external) Create(ctx context.Context, cr *identityv1alpha1.SAMLBroker) (managed.ExternalCreation, error) {
	cr.Status.SetConditions(xpv2.Creating())
	d := desired(cr)
	key, err := mutationKey("create", "", 0, d)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	r, err := route(http.MethodPost, "/api/v1/identity/saml-brokers")
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	var result samlMutationResponse
	body := samlBrokerRequest{SAMLBrokerParameters: d, IdempotencyKey: key}
	if _, err := e.client.Do(ctx, r, nil, nil, body, nil, &result); err != nil {
		return managed.ExternalCreation{}, err
	}
	if strings.TrimSpace(result.Broker.ID) == "" {
		return managed.ExternalCreation{}, fmt.Errorf("Product API returned SAML broker without id")
	}
	meta.SetExternalName(cr, result.Broker.ID)
	projectStatus(cr, result.Broker, result.Job)
	return managed.ExternalCreation{ConnectionDetails: managed.ConnectionDetails{}}, nil
}

func (e *external) Update(ctx context.Context, cr *identityv1alpha1.SAMLBroker) (managed.ExternalUpdate, error) {
	id := strings.TrimSpace(meta.GetExternalName(cr))
	if id == "" {
		return managed.ExternalUpdate{}, fmt.Errorf("cannot update SAML broker without external name")
	}
	revision := cr.Status.AtProvider.Revision
	if revision <= 0 {
		return managed.ExternalUpdate{}, fmt.Errorf("cannot update SAML broker %s without positive observed revision", id)
	}
	d := desired(cr)
	key, err := mutationKey("update", id, revision, d)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	r, err := route(http.MethodPut, "/api/v1/identity/saml-brokers/{id}")
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	headers := make(http.Header)
	headers.Set("If-Match", strconv.FormatInt(revision, 10))
	var result samlMutationResponse
	body := samlBrokerRequest{SAMLBrokerParameters: d, IdempotencyKey: key}
	if _, err := e.client.Do(ctx, r, map[string]string{"id": id}, nil, body, headers, &result); err != nil {
		return managed.ExternalUpdate{}, err
	}
	projectStatus(cr, result.Broker, result.Job)
	return managed.ExternalUpdate{ConnectionDetails: managed.ConnectionDetails{}}, nil
}

func (e *external) Delete(ctx context.Context, cr *identityv1alpha1.SAMLBroker) (managed.ExternalDelete, error) {
	cr.Status.SetConditions(xpv2.Deleting())
	id := strings.TrimSpace(meta.GetExternalName(cr))
	if id == "" {
		return managed.ExternalDelete{}, nil
	}
	current, exists, err := lookupBroker(ctx, e.client, cr.Spec.ForProvider.OrganizationID, id)
	if err != nil {
		return managed.ExternalDelete{}, err
	}
	if !exists {
		return managed.ExternalDelete{}, nil
	}
	if current.Revision <= 0 {
		return managed.ExternalDelete{}, fmt.Errorf("cannot delete SAML broker %s without positive observed revision", id)
	}
	key, err := mutationKey("delete", id, current.Revision, nil)
	if err != nil {
		return managed.ExternalDelete{}, err
	}
	r, err := route(http.MethodDelete, "/api/v1/identity/saml-brokers/{id}")
	if err != nil {
		return managed.ExternalDelete{}, err
	}
	headers := make(http.Header)
	headers.Set("If-Match", strconv.FormatInt(current.Revision, 10))
	var result samlMutationResponse
	if _, err := e.client.Do(ctx, r, map[string]string{"id": id}, nil, map[string]string{"idempotencyKey": key}, headers, &result); err != nil {
		return managed.ExternalDelete{}, err
	}
	projectStatus(cr, result.Broker, result.Job)
	return managed.ExternalDelete{}, nil
}

func (e *external) Disconnect(context.Context) error { return nil }
