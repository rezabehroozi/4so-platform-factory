package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	foursoprovider "platform.4so.io/factory/providers/terraform/internal/provider"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with debugger support")
	flag.Parse()

	if err := providerserver.Serve(
		context.Background(),
		foursoprovider.New(version),
		providerserver.ServeOpts{
			Address: "registry.terraform.io/4so/fourso",
			Debug:   debug,
		},
	); err != nil {
		log.Fatal(err)
	}
}
