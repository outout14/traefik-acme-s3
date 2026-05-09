package app

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

const lockRefreshInterval = time.Minute

func (a *App) startLockRefresh() func() {
	if a.state == nil {
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(lockRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.state.RefreshLock(); err != nil {
					log.Warn().Err(err).Msg("Unable to refresh distributed lock")
				}
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}
