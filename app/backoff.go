package app

import (
	"time"

	"github.com/outout14/traefik-acme-s3/pkg/certcloset"
	"github.com/rs/zerolog/log"
)

// loadFailureState returns the current failure state from S3.
// Returns an empty state when a.state is nil (e.g. in unit tests without state injection).
func (a *App) loadFailureState() (*certcloset.FailureState, error) {
	if a.state == nil {
		return &certcloset.FailureState{LastFailure: make(map[string]string)}, nil
	}
	return a.state.LoadFailureState()
}

// saveFailureState persists the failure state to S3. No-op when a.state is nil.
func (a *App) saveFailureState(s *certcloset.FailureState) error {
	if a.state == nil {
		return nil
	}
	return a.state.StoreFailureState(s)
}

// isInBackoff returns true if domain failed recently within backoffMinutes.
func (a *App) isInBackoff(s *certcloset.FailureState, domain string, backoffMinutes int) bool {
	if s == nil || backoffMinutes <= 0 {
		return false
	}
	tStr, ok := s.LastFailure[domain]
	if !ok {
		return false
	}
	t, err := time.Parse(time.RFC3339, tStr)
	if err != nil {
		return false
	}
	return time.Since(t) < time.Duration(backoffMinutes)*time.Minute
}

func (a *App) recordFailure(s *certcloset.FailureState, domain string) {
	if s == nil || s.LastFailure == nil {
		return
	}
	s.LastFailure[domain] = time.Now().Format(time.RFC3339)
}

func (a *App) clearFailure(s *certcloset.FailureState, domain string) {
	if s == nil || s.LastFailure == nil {
		return
	}
	delete(s.LastFailure, domain)
}

func (a *App) getDomainsWithRetry(maxAttempts int, backoff time.Duration) ([]string, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		domains, err := a.traefikApi.GetDomains()
		if err == nil {
			return domains, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			log.Warn().Err(err).Int("attempt", attempt).Int("max", maxAttempts).
				Msg("Traefik API GetDomains failed, retrying after backoff")
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return nil, lastErr
}
