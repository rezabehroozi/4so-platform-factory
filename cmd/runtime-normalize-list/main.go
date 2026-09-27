package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"platform.4so.io/factory/catalog"
)

func main() {
	component := flag.String("component", "", "component identity")
	release := flag.String("release", "", "exact release")
	in := flag.String("in", "", "input Kubernetes List JSON")
	out := flag.String("out", "", "normalized Kubernetes List JSON")
	evidence := flag.String("evidence", "", "normalization evidence JSON")
	flag.Parse()
	if strings.TrimSpace(*component)=="" || strings.TrimSpace(*release)=="" || strings.TrimSpace(*in)=="" || strings.TrimSpace(*out)=="" || strings.TrimSpace(*evidence)=="" {
		fatal("component, release, in, out and evidence are required")
	}
	raw, err := os.ReadFile(*in); if err != nil { fatalErr("read input",err) }
	var list struct {
		APIVersion string `json:"apiVersion"`
		Kind string `json:"kind"`
		Items []map[string]any `json:"items"`
	}
	if err=json.Unmarshal(raw,&list); err!=nil { fatalErr("decode input",err) }
	if list.APIVersion!="v1" || list.Kind!="List" || len(list.Items)==0 { fatal("input must be non-empty v1/List") }
	ev, err := catalog.RuntimeNormalizeResources(*component,*release,list.Items); if err != nil { fatalErr("normalize runtime resources",err) }
	writeJSON(*out,map[string]any{"apiVersion":"v1","kind":"List","items":list.Items})
	writeJSON(*evidence,ev)
	fmt.Printf("RUNTIME_NORMALIZE_LIST_PASS component=%s release=%s applied=%t resources=%d authority=%s\n",*component,*release,ev.Applied,len(list.Items),ev.Authority)
}
func writeJSON(path string,v any){ if err:=os.MkdirAll(filepath.Dir(path),0o755); err!=nil{fatalErr("mkdir",err)}; raw,err:=json.MarshalIndent(v,"","  ");if err!=nil{fatalErr("marshal",err)};raw=append(raw,'\n');if err=os.WriteFile(path,raw,0o600);err!=nil{fatalErr("write",err)}}
func fatal(s string){fmt.Fprintln(os.Stderr,s);os.Exit(2)}
func fatalErr(s string,e error){fatal(s+": "+e.Error())}
