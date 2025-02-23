package app

import (
	"context"
	"os"

	"github.com/outout14/traefik-acme-s3/pkg/buckcert"
	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func (a *App) initLog() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if a.config.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Debug().Msg("Debug mode enabled")
}

func (a *App) initS3() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatal().Err(err).Msg("unable to load AWS SDK config")
	}
	a.s3 = s3.NewFromConfig(cfg)

	_, err = a.s3.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: &a.config.Bucket,
	})
	if err != nil {
		log.Fatal().Err(err).Str("bucket", a.config.Bucket).Msg("unable to access S3 bucket")
	}
	log.Info().Str("bucket", a.config.Bucket).Msg("S3 bucket access OK")
}

func (a *App) initBuckcert() {
	var err error
	a.buckcert, err = buckcert.NewBuckcert(a.config.Letsencrypt)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create buckcert")
	}
	log.Debug().Msg("Buckcert initialized")
}

func (a *App) initCloset() {
	var err error
	a.closet, err = certcloset.NewCertCloset(a.config.Closet)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create cert closet")
	}
	log.Debug().Msg("CertCloset initialized")
}
