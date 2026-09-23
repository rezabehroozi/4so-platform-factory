package openchoreo

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func admittedFixture() RuntimeSource {
	s:=SelectedRuntimeSource()
	s.Resolved=true
	s.MirrorReady=true
	s.SourceArchiveSHA256="sha256:"+strings.Repeat("a",64)
	s.Planes[0].ChartSHA256="sha256:"+strings.Repeat("b",64)
	s.Planes[0].ValuesSHA256="sha256:"+strings.Repeat("c",64)
	s.Planes[0].RenderManifestSHA256="sha256:"+strings.Repeat("d",64)
	s.Planes[1].ChartSHA256="sha256:"+strings.Repeat("e",64)
	s.Planes[1].ValuesSHA256="sha256:"+strings.Repeat("f",64)
	s.Planes[1].RenderManifestSHA256="sha256:"+strings.Repeat("1",64)
	s.Images=[]ImageMirror{{SourceReference:"ghcr.io/openchoreo/controller@sha256:"+strings.Repeat("2",64),Digest:"sha256:"+strings.Repeat("2",64),MirrorReference:"zot.internal/openchoreo/controller@sha256:"+strings.Repeat("2",64)}}
	s.ExecutorImageDigest="sha256:"+strings.Repeat("3",64)
	s.ExecutorImageReference="zot.internal/4so/openchoreo-runtime@sha256:"+strings.Repeat("3",64)
	return s
}

func TestSelectedOpenChoreoSourceIsExactButUnresolvedInGit(t *testing.T){
	s:=SelectedRuntimeSource()
	if s.Version!="1.3.0"||s.UpstreamCommit!=ReviewedUpstreamCommit||len(s.Planes)!=2{t.Fatalf("selection=%#v",s)}
	if err:=ValidateRuntimeExecutionSource(s);err==nil{t.Fatal("unresolved source was admitted")}
	raw,err:=os.ReadFile("../../runtime/openchoreo/source-selection.json");if err!=nil{t.Fatal(err)}
	var doc struct{Spec RuntimeSource `json:"spec"`};if err=json.Unmarshal(raw,&doc);err!=nil{t.Fatal(err)}
	if doc.Spec.Resolved||doc.Spec.MirrorReady||doc.Spec.ExecutorImageReference!=""{t.Fatalf("git selection must remain unresolved: %#v",doc.Spec)}
}

func TestOpenChoreoRuntimeSourceRequiresFactoryAuthorityBoundaries(t *testing.T){
	s:=admittedFixture()
	if err:=ValidateRuntimeExecutionSource(s);err!=nil{t.Fatal(err)}
	d1,err:=RuntimeSourceDigest(s);if err!=nil{t.Fatal(err)}
	d2,err:=RuntimeSourceDigest(s);if err!=nil||d1!=d2{t.Fatalf("digest unstable: %s %s %v",d1,d2,err)}
	for name,mutate:=range map[string]func(*RuntimeSource){
		"backstage":func(v *RuntimeSource){v.BackstageEnabled=true},
		"workflow":func(v *RuntimeSource){v.WorkflowPlaneEnabled=true},
		"observability":func(v *RuntimeSource){v.ObservabilityPlaneEnabled=true},
		"upstream-mcp":func(v *RuntimeSource){v.OpenChoreoMCPEnabled=true},
		"wrong-build":func(v *RuntimeSource){v.BuildAuthority="tekton"},
		"wrong-registry":func(v *RuntimeSource){v.RegistryAuthority="external"},
		"mirror-digest":func(v *RuntimeSource){v.Images[0].MirrorReference="zot.internal/openchoreo/controller@sha256:"+strings.Repeat("4",64)},
	}{
		broken:=s;broken.Planes=append([]PlaneSource(nil),s.Planes...);broken.Images=append([]ImageMirror(nil),s.Images...);mutate(&broken)
		if err:=ValidateRuntimeExecutionSource(broken);err==nil{t.Fatalf("%s negative control admitted",name)}
	}
}
