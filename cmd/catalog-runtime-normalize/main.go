package main
import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"platform.4so.io/factory/catalog"
)
func main() {
	component:=flag.String("component","","component")
	release:=flag.String("release","","release")
	in:=flag.String("in","","input JSON resource array")
	out:=flag.String("out","","output Kubernetes List JSON")
	evidence:=flag.String("evidence","","normalization evidence JSON")
	flag.Parse()
	if *component==""||*release==""||*in==""||*out==""||*evidence=="" { panic("component/release/in/out/evidence required") }
	raw,err:=os.ReadFile(*in); if err!=nil { panic(err) }
	var resources []map[string]any
	if err=json.Unmarshal(raw,&resources);err!=nil { panic(err) }
	normalized,ev,err:=catalog.RuntimeNormalizeResourceList(*component,*release,resources);if err!=nil{panic(err)}
	list:=map[string]any{"apiVersion":"v1","kind":"List","items":normalized}
	encoded,_:=json.Marshal(list);if err=os.WriteFile(*out,encoded,0600);err!=nil{panic(err)}
	evRaw,_:=json.MarshalIndent(ev,"","  ");if err=os.WriteFile(*evidence,append(evRaw,'\n'),0600);err!=nil{panic(err)}
	fmt.Printf("RUNTIME_NORMALIZATION_PASS authority=%s removed=%d\n",ev.Authority,ev.RemovedInvalidDefaultLocations)
}
