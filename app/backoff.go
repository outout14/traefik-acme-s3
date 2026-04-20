package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

const failureStateFile = "renew_failures.json"

// failureState holds last failure time per domain (RFC3339).
type failureState struct {
	LastFailure map[string]string `json:"last_failure"`
}

func (a *App) loadFailureState(stateDir string) (*failureState, error) {
	if stateDir == "" {
		return &failureState{LastFailure: make(map[string]string)}, nil
	}
	path := filepath.Join(stateDir, failureStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &failureState{LastFailure: make(map[string]string)}, nil
		}
		return nil, err
	}
	var s failureState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.LastFailure == nil {
		s.LastFailure = make(map[string]string)
	}
	return &s, nil
}

func (a *App) saveFailureState(stateDir string, s *failureState) error {
	if stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(stateDir, failureStateFile)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// isInBackoff returns true if domain failed recently within backoffMinutes.
func (a *App) isInBackoff(s *failureState, domain string, backoffMinutes int) bool {
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

func (a *App) recordFailure(s *failureState, domain string) {
	if s == nil || s.LastFailure == nil {
		return
	}
	s.LastFailure[domain] = time.Now().Format(time.RFC3339)
}

func (a *App) clearFailure(s *failureState, domain string) {
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
