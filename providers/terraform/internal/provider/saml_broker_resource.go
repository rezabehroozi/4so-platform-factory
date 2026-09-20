package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	factorysdk "platform.4so.io/factory/sdk/go"
)

var _ resource.Resource = &samlBrokerResource{}
var _ resource.ResourceWithConfigure = &samlBrokerResource{}
var _ resource.ResourceWithImportState = &samlBrokerResource{}

type samlBrokerResource struct {
	client *factorysdk.Client
}

type samlBrokerResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	OrganizationID          types.String `tfsdk:"organization_id"`
	Alias                   types.String `tfsdk:"alias"`
	KeycloakAlias           types.String `tfsdk:"keycloak_alias"`
	DisplayName             types.String `tfsdk:"display_name"`
	EntityID                types.String `tfsdk:"entity_id"`
	SingleSignOnServiceURL  types.String `tfsdk:"single_sign_on_service_url"`
	SingleLogoutServiceURL  types.String `tfsdk:"single_logout_service_url"`
	SigningCertificate      types.String `tfsdk:"signing_certificate"`
	NameIDPolicyFormat      types.String `tfsdk:"name_id_policy_format"`
	WantAuthnRequestsSigned types.Bool   `tfsdk:"want_authn_requests_signed"`
	Enabled                 types.Bool   `tfsdk:"enabled"`
	Revision                types.Int64  `tfsdk:"revision"`
	BrokerState             types.String `tfsdk:"broker_state"`
	DesiredDigest           types.String `tfsdk:"desired_digest"`
	ObservedDigest          types.String `tfsdk:"observed_digest"`
	RequestedBy             types.String `tfsdk:"requested_by"`
	LastError               types.String `tfsdk:"last_error"`
	JobID                   types.String `tfsdk:"job_id"`
	JobState                types.String `tfsdk:"job_state"`
	ApprovalRequired        types.Bool   `tfsdk:"approval_required"`
}

type samlBrokerDesired struct {
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

type samlBrokerRequest struct {
	samlBrokerDesired
	IdempotencyKey string `json:"idempotencyKey"`
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
	Broker           samlBrokerAPI       `json:"broker"`
	Job              identityAdminJobAPI `json:"job"`
	IdempotentReplay bool                `json:"idempotentReplay"`
}

func NewSAMLBrokerResource() resource.Resource { return &samlBrokerResource{} }

func (r *samlBrokerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_saml_broker"
}

func (r *samlBrokerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a 4SO SAML broker through the Product API durable identity-admin workflow. Terraform never self-approves identity changes.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"organization_id": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"alias": schema.StringAttribute{Required: true},
			"keycloak_alias": schema.StringAttribute{Computed: true},
			"display_name": schema.StringAttribute{Required: true},
			"entity_id": schema.StringAttribute{Required: true},
			"single_sign_on_service_url": schema.StringAttribute{Required: true},
			"single_logout_service_url": schema.StringAttribute{Optional: true, Computed: true},
			"signing_certificate": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Canonical SAML signing certificate trust material. This is public certificate material, never a private key.",
			},
			"name_id_policy_format": schema.StringAttribute{Optional: true, Computed: true},
			"want_authn_requests_signed": schema.BoolAttribute{Required: true},
			"enabled": schema.BoolAttribute{Required: true},
			"revision": schema.Int64Attribute{Computed: true},
			"broker_state": schema.StringAttribute{Computed: true},
			"desired_digest": schema.StringAttribute{Computed: true},
			"observed_digest": schema.StringAttribute{Computed: true},
			"requested_by": schema.StringAttribute{Computed: true},
			"last_error": schema.StringAttribute{Computed: true},
			"job_id": schema.StringAttribute{Computed: true},
			"job_state": schema.StringAttribute{Computed: true},
			"approval_required": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "True when the Product API durable identity-admin job requires approval from a different authorized actor.",
			},
		},
	}
}

func (r *samlBrokerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*factorysdk.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *factorysdk.Client, got %T.", req.ProviderData))
		return
	}
	r.client = client
}

func desiredFromModel(data samlBrokerResourceModel) samlBrokerDesired {
	return samlBrokerDesired{
		OrganizationID: strings.TrimSpace(data.OrganizationID.ValueString()),
		Alias: strings.TrimSpace(data.Alias.ValueString()),
		DisplayName: strings.TrimSpace(data.DisplayName.ValueString()),
		EntityID: strings.TrimSpace(data.EntityID.ValueString()),
		SingleSignOnServiceURL: strings.TrimSpace(data.SingleSignOnServiceURL.ValueString()),
		SingleLogoutServiceURL: strings.TrimSpace(data.SingleLogoutServiceURL.ValueString()),
		SigningCertificate: strings.TrimSpace(data.SigningCertificate.ValueString()),
		NameIDPolicyFormat: strings.TrimSpace(data.NameIDPolicyFormat.ValueString()),
		WantAuthnRequestsSigned: data.WantAuthnRequestsSigned.ValueBool(),
		Enabled: data.Enabled.ValueBool(),
	}
}

func samlMutationKey(action, id string, revision int64, desired any) string {
	raw, _ := json.Marshal(struct {
		Action   string `json:"action"`
		ID       string `json:"id,omitempty"`
		Revision int64  `json:"revision,omitempty"`
		Desired  any    `json:"desired,omitempty"`
	}{Action: action, ID: id, Revision: revision, Desired: desired})
	sum := sha256.Sum256(raw)
	return "terraform-saml-" + action + "-" + hex.EncodeToString(sum[:16])
}

func applyBrokerState(data *samlBrokerResourceModel, broker samlBrokerAPI, job identityAdminJobAPI) {
	data.ID = types.StringValue(broker.ID)
	data.OrganizationID = types.StringValue(broker.OrganizationID)
	data.Alias = types.StringValue(broker.Alias)
	data.KeycloakAlias = types.StringValue(broker.KeycloakAlias)
	data.DisplayName = types.StringValue(broker.DisplayName)
	data.EntityID = types.StringValue(broker.EntityID)
	data.SingleSignOnServiceURL = types.StringValue(broker.SingleSignOnServiceURL)
	data.SingleLogoutServiceURL = types.StringValue(broker.SingleLogoutServiceURL)
	data.SigningCertificate = types.StringValue(broker.SigningCertificate)
	data.NameIDPolicyFormat = types.StringValue(broker.NameIDPolicyFormat)
	data.WantAuthnRequestsSigned = types.BoolValue(broker.WantAuthnRequestsSigned)
	data.Enabled = types.BoolValue(broker.Enabled)
	data.Revision = types.Int64Value(broker.Revision)
	data.BrokerState = types.StringValue(broker.State)
	data.DesiredDigest = types.StringValue(broker.DesiredDigest)
	data.ObservedDigest = types.StringValue(broker.ObservedDigest)
	data.RequestedBy = types.StringValue(broker.RequestedBy)
	data.LastError = types.StringValue(broker.LastError)
	if job.ID != "" {
		data.JobID = types.StringValue(job.ID)
		data.JobState = types.StringValue(job.State)
		data.ApprovalRequired = types.BoolValue(job.State == "AWAITING_APPROVAL")
	} else if data.JobID.IsNull() || data.JobID.IsUnknown() {
		data.JobID = types.StringValue("")
		data.JobState = types.StringValue("")
		data.ApprovalRequired = types.BoolValue(false)
	}
}

func approvalWarning(job identityAdminJobAPI) (string, string) {
	return "SAML broker approval required",
		fmt.Sprintf("Identity admin job %s is %s. A different authorized actor must approve it; the Terraform provider deliberately never self-approves.", job.ID, job.State)
}

func (r *samlBrokerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "No 4SO Product API client is available.")
		return
	}
	var data samlBrokerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	desired := desiredFromModel(data)
	body := samlBrokerRequest{
		samlBrokerDesired: desired,
		IdempotencyKey: samlMutationKey("create", "", 0, desired),
	}
	route, err := productRoute("POST", "/api/v1/identity/saml-brokers")
	if err != nil {
		resp.Diagnostics.AddError("Product API contract error", err.Error())
		return
	}
	var result samlMutationResponse
	if _, err = r.client.Do(ctx, route, nil, nil, body, nil, &result); err != nil {
		resp.Diagnostics.AddError("Unable to request SAML broker creation", err.Error())
		return
	}
	applyBrokerState(&data, result.Broker, result.Job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if result.Job.State == "AWAITING_APPROVAL" {
		title, detail := approvalWarning(result.Job)
		resp.Diagnostics.AddWarning(title, detail)
	}
}

func (r *samlBrokerResource) lookupBroker(ctx context.Context, organizationID, id string) (samlBrokerAPI, bool, error) {
	route, err := productRoute("GET", "/api/v1/identity/saml-brokers")
	if err != nil {
		return samlBrokerAPI{}, false, err
	}
	query := url.Values{"organizationId": []string{organizationID}}
	var brokers []samlBrokerAPI
	if _, err = r.client.Do(ctx, route, nil, query, nil, nil, &brokers); err != nil {
		return samlBrokerAPI{}, false, err
	}
	for _, broker := range brokers {
		if broker.ID == id {
			return broker, true, nil
		}
	}
	return samlBrokerAPI{}, false, nil
}

func (r *samlBrokerResource) refreshJob(ctx context.Context, organizationID, jobID string) (identityAdminJobAPI, error) {
	if strings.TrimSpace(jobID) == "" {
		return identityAdminJobAPI{}, nil
	}
	route, err := productRoute("GET", "/api/v1/identity/admin-jobs")
	if err != nil {
		return identityAdminJobAPI{}, err
	}
	query := url.Values{"organizationId": []string{organizationID}}
	var jobs []identityAdminJobAPI
	if _, err = r.client.Do(ctx, route, nil, query, nil, nil, &jobs); err != nil {
		return identityAdminJobAPI{}, err
	}
	for _, job := range jobs {
		if job.ID == jobID {
			return job, nil
		}
	}
	return identityAdminJobAPI{}, nil
}

func (r *samlBrokerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "No 4SO Product API client is available.")
		return
	}
	var data samlBrokerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	broker, found, err := r.lookupBroker(ctx, data.OrganizationID.ValueString(), data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read SAML broker", err.Error())
		return
	}
	if !found || broker.State == "DELETED" {
		resp.State.RemoveResource(ctx)
		return
	}
	jobID := ""
	if !data.JobID.IsNull() && !data.JobID.IsUnknown() {
		jobID = data.JobID.ValueString()
	}
	job, err := r.refreshJob(ctx, broker.OrganizationID, jobID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to refresh SAML broker job", err.Error())
		return
	}
	applyBrokerState(&data, broker, job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *samlBrokerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "No 4SO Product API client is available.")
		return
	}
	var plan, state samlBrokerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.Revision.IsNull() || state.Revision.IsUnknown() || state.Revision.ValueInt64() <= 0 {
		resp.Diagnostics.AddError("Missing SAML broker revision", "Terraform state has no valid optimistic-concurrency revision.")
		return
	}
	desired := desiredFromModel(plan)
	revision := state.Revision.ValueInt64()
	body := samlBrokerRequest{
		samlBrokerDesired: desired,
		IdempotencyKey: samlMutationKey("update", state.ID.ValueString(), revision, desired),
	}
	route, err := productRoute("PUT", "/api/v1/identity/saml-brokers/{id}")
	if err != nil {
		resp.Diagnostics.AddError("Product API contract error", err.Error())
		return
	}
	headers := make(http.Header)
	headers.Set("If-Match", strconv.FormatInt(revision, 10))
	var result samlMutationResponse
	if _, err = r.client.Do(ctx, route, map[string]string{"id": state.ID.ValueString()}, nil, body, headers, &result); err != nil {
		resp.Diagnostics.AddError("Unable to request SAML broker update", err.Error())
		return
	}
	applyBrokerState(&plan, result.Broker, result.Job)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if result.Job.State == "AWAITING_APPROVAL" {
		title, detail := approvalWarning(result.Job)
		resp.Diagnostics.AddWarning(title, detail)
	}
}

func (r *samlBrokerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "No 4SO Product API client is available.")
		return
	}
	var state samlBrokerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, found, err := r.lookupBroker(ctx, state.OrganizationID.ValueString(), state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to inspect SAML broker before deletion", err.Error())
		return
	}
	if !found || current.State == "DELETED" {
		return
	}
	if state.Revision.IsNull() || state.Revision.IsUnknown() || current.Revision != state.Revision.ValueInt64() {
		resp.Diagnostics.AddError(
			"SAML broker revision changed",
			fmt.Sprintf("Remote revision is %d while Terraform state revision is %d. Refresh state before deletion; the provider will not guess a concurrency fence.", current.Revision, state.Revision.ValueInt64()),
		)
		return
	}
	route, err := productRoute("DELETE", "/api/v1/identity/saml-brokers/{id}")
	if err != nil {
		resp.Diagnostics.AddError("Product API contract error", err.Error())
		return
	}
	revision := current.Revision
	body := map[string]string{
		"idempotencyKey": samlMutationKey("delete", current.ID, revision, nil),
	}
	headers := make(http.Header)
	headers.Set("If-Match", strconv.FormatInt(revision, 10))
	var result samlMutationResponse
	if _, err = r.client.Do(ctx, route, map[string]string{"id": current.ID}, nil, body, headers, &result); err != nil {
		resp.Diagnostics.AddError("Unable to request SAML broker deletion", err.Error())
		return
	}
	if result.Broker.State != "DELETED" {
		resp.Diagnostics.AddError(
			"SAML broker deletion is not complete",
			fmt.Sprintf("Identity admin job %s is %s and broker state is %s. Terraform keeps the resource in state until a different authorized actor approves the deletion and Product API reports DELETED.", result.Job.ID, result.Job.State, result.Broker.State),
		)
	}
}

func (r *samlBrokerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	organizationID, brokerID, ok := strings.Cut(strings.TrimSpace(req.ID), "/")
	if !ok || strings.TrimSpace(organizationID) == "" || strings.TrimSpace(brokerID) == "" || strings.Contains(brokerID, "/") {
		resp.Diagnostics.AddError("Invalid SAML broker import ID", "Use organization_id/broker_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("organization_id"), organizationID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), brokerID)...)
}
