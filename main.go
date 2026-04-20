package main

import (
	"github.com/alecthomas/kong"
	"github.com/outout14/traefik-acme-s3/app"
)

type RenewCmd struct {
	app.RenewConfig
}

func (r *RenewCmd) Run(ctx *app.Config) error {
	a := app.App{}
	a.Init(*ctx)
	defer a.Close()
	a.Renew(r.RenewConfig)
	return nil
}

type SyncCmd struct {
	app.SyncConfig
}

func (s *SyncCmd) Run(ctx *app.Config) error {
	a := app.App{}
	a.Init(*ctx)
	defer a.Close()
	return a.Sync(s.SyncConfig)
}

var cli struct {
	app.Config

	Renew RenewCmd `cmd:"" help:"Generate or renew certificates."`
	Sync  SyncCmd  `cmd:"" help:"Synchronize the certificates."`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("TAS3"),
		kong.Description("TAS3 is a tool to manage TLS certificates."))

	err := ctx.Run(&cli.Config)
	ctx.FatalIfErrorf(err)
}
