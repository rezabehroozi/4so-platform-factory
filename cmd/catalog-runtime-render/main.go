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
	component := flag.String("component", "", "canonical catalog component name")
	namespace := flag.String("namespace", "", "target namespace")
	releaseID := flag.String("release-id", "", "catalog release identity used for rendering")
	out := flag.String("out", "", "output Kubernetes List JSON path")
	evidenceOut := flag.String("evidence", "", "output render evidence JSON path")
	flag.Parse()
	if strings.TrimSpace(*component)=="" || strings.TrimSpace(*namespace)=="" || strings.TrimSpace(*releaseID)=="" || strings.TrimSpace(*out)=="" || strings.TrimSpace(*evidenceOut)=="" {
		fatal("component, namespace, release-id, out and evidence are required")
	}
	components, err := catalog.Load()
	if err != nil { fatalErr("load catalog", err) }
	c, ok := components[strings.TrimSpace(*component)]
	if !ok { fatal("component is not present in canonical catalog") }
	rendered, err := catalog.RenderComponent(c, strings.TrimSpace(*namespace), strings.TrimSpace(*releaseID))
	if err != nil { fatalErr("render component", err) }
	list := map[string]any{"apiVersion":"v1","kind":"List","items":rendered.Resources}
	writeJSON(*out, list)
	writeJSON(*evidenceOut, rendered)
	fmt.Printf("CATALOG_RUNTIME_RENDER_PASS component=%s version=%s resources=%d digest=%s\n", rendered.Name, rendered.Version, len(rendered.Resources), rendered.RenderedDigest)
}

func writeJSON(path string, value any) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { fatalErr("create output directory", err) }
	raw, err := json.MarshalIndent(value, "", "  "); if err != nil { fatalErr("marshal output", err) }
	raw = append(raw, '\n')
	if err = os.WriteFile(path, raw, 0o600); err != nil { fatalErr("write output", err) }
}
func fatal(msg string) { fmt.Fprintln(os.Stderr, msg); os.Exit(2) }
func fatalErr(msg string, err error) { fatal(msg+": "+err.Error()) }
