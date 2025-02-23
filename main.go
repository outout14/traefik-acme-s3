package main

import (
	"github.com/alecthomas/kong"
	"github.com/outout14/traefik-acme-s3/app"
)

type RenewCmd struct {
	// Force     bool `help:"Force removal."`
}

func (r *RenewCmd) Run(ctx *app.Config) error {
	app := app.App{}
	app.Init(*ctx)
	app.Renew()
	return nil
}

type SyncCmd struct {
	// Paths []string `arg:"" optional:"" name:"path" help:"Paths to list." type:"path"`
}

func (s *SyncCmd) Run(ctx *app.Config) error {
	return nil
}

var cli struct {
	app.Config

	Renew   RenewCmd `cmd:"" help:"Generate or renew certificates."`
	Synchro SyncCmd  `cmd:"" help:"Synchronize the certificates."`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("TAS3"),
		kong.Description("TAS3 is a tool to manage TLS certificates."))

	err := ctx.Run(&cli.Config)
	ctx.FatalIfErrorf(err)
}
