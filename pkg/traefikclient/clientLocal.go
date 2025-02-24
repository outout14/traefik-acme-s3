package traefikclient

type LocalClient struct {
}

type LocalConfig struct {
	OutputDir      string `env:"TRAEFIK_OUTPUT_DIR" required:"" help:"Traefik output directory to output the certificate configuration files."`
	CertificateDir string `env:"TRAEFIK_CERTIFICATE_DIR" required:"" help:"Traefik certificate directory to output the certificate files."`
}
