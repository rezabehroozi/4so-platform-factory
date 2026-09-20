package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	factorysdk "platform.4so.io/factory/sdk/go"
)

var _ datasource.DataSource = &versionDataSource{}
var _ datasource.DataSourceWithConfigure = &versionDataSource{}

type versionDataSource struct {
	client *factorysdk.Client
}

type versionDataSourceModel struct {
	Product types.String `tfsdk:"product"`
	Version types.String `tfsdk:"version"`
}

func NewVersionDataSource() datasource.DataSource { return &versionDataSource{} }

func (d *versionDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_version"
}

func (d *versionDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the authoritative 4SO Platform Factory Product API identity and version.",
		Attributes: map[string]schema.Attribute{
			"product": schema.StringAttribute{Computed: true},
			"version": schema.StringAttribute{Computed: true},
		},
	}
}

func (d *versionDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*factorysdk.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *factorysdk.Client, got %T.", req.ProviderData))
		return
	}
	d.client = client
}

func (d *versionDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider is not configured", "No 4SO Product API client is available.")
		return
	}
	route, err := productRoute("GET", "/api/v1/version")
	if err != nil {
		resp.Diagnostics.AddError("Product API contract error", err.Error())
		return
	}
	var out struct {
		Product string `json:"product"`
		Version string `json:"version"`
	}
	if _, err = d.client.Do(ctx, route, nil, nil, nil, nil, &out); err != nil {
		resp.Diagnostics.AddError("Unable to read 4SO version", err.Error())
		return
	}
	state := versionDataSourceModel{
		Product: types.StringValue(out.Product),
		Version: types.StringValue(out.Version),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
