package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"platform.4so.io/factory/internal/runtimeupgrade"
)

func main() {
	in := flag.String("in", "", "exact component upgrade edge JSON")
	flag.Parse()
	if *in == "" { fatal("in is required") }
	raw, err := os.ReadFile(*in); if err != nil { fatalErr("read edge",err) }
	var edge runtimeupgrade.Edge
	if err=json.Unmarshal(raw,&edge); err!=nil { fatalErr("decode edge",err) }
	digest, err := runtimeupgrade.PlanDigest(edge); if err!=nil { fatalErr("validate edge",err) }
	out:=map[string]any{"authority":runtimeupgrade.Authority,"component":edge.Component,"fromRelease":edge.FromRelease,"toRelease":edge.ToRelease,"planDigest":digest}
	enc,_:=json.Marshal(out);fmt.Println(string(enc))
}
func fatal(s string){fmt.Fprintln(os.Stderr,s);os.Exit(2)}
func fatalErr(s string,e error){fatal(s+": "+e.Error())}
