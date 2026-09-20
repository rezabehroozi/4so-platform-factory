package provider

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	factorysdk "platform.4so.io/factory/sdk/go"
)

var _ provider.Provider = &fourSOProvider{}

type fourSOProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &fourSOProvider{version: version} }
}

func (p *fourSOProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "fourso"
	resp.Version = p.version
}

func (p *fourSOProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "4SO Platform Factory provider. Product API remains the only lifecycle authority; the provider does not duplicate approvals, retries, or business policy.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Base URL of the stable 4SO Product API. May also be supplied with FOURSO_ENDPOINT.",
				Optional: true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Bearer token for the current authorized user or service account. May also be supplied with FOURSO_TOKEN.",
				Optional: true,
				Sensitive: true,
			},
		},
	}
}

func configuredString(value types.String, environment string) (string, bool) {
	if value.IsUnknown() {
		return "", false
	}
	if !value.IsNull() {
		if configured := strings.TrimSpace(value.ValueString()); configured != "" {
			return configured, true
		}
	}
	if configured := strings.TrimSpace(os.Getenv(environment)); configured != "" {
		return configured, true
	}
	return "", true
}

func (p *fourSOProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint, endpointKnown := configuredString(data.Endpoint, "FOURSO_ENDPOINT")
	if !endpointKnown {
		resp.Diagnostics.AddError("Unknown 4SO endpoint", "The endpoint must be known before provider configuration.")
		return
	}
	if endpoint == "" {
		resp.Diagnostics.AddError("Missing 4SO endpoint", "Set provider endpoint or FOURSO_ENDPOINT.")
		return
	}
	token, tokenKnown := configuredString(data.Token, "FOURSO_TOKEN")
	if !tokenKnown {
		resp.Diagnostics.AddError("Unknown 4SO token", "The token must be known before provider configuration.")
		return
	}

	client, err := factorysdk.NewClient(endpoint, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		resp.Diagnostics.AddError("Invalid 4SO endpoint", err.Error())
		return
	}
	client.BearerToken = token
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *fourSOProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewVersionDataSource}
}

func (p *fourSOProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewSAMLBrokerResource}
}
