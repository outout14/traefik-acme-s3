package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// resolveToken returns the effective HTTP trigger token.
// env var takes priority; falls back to reading from file (Docker secret).
func resolveToken(envToken, filePath string) (string, error) {
	if envToken != "" {
		return envToken, nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("reading HTTP token file %q: %w", filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

func authMiddleware(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(limiter *rate.Limiter, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startMetricsServer runs a /metrics-only HTTP server. Blocks until ctx is cancelled and
// the server drains (max 5 s). Intended to be called in a goroutine tracked by a WaitGroup.
func startMetricsServer(ctx context.Context, addr string, a *App) {
	if a.metrics == nil {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(a.metrics.registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	log.Info().Str("addr", addr).Msg("metrics server listening")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("metrics server error")
	}
}

// startTriggerServer runs the trigger/health server. Blocks until ctx is cancelled and the
// server drains (max 5 s). Intended to be called in a goroutine tracked by a WaitGroup.
func (a *App) startTriggerServer(ctx context.Context, dcfg DaemonConfig, token string, triggerCh chan<- struct{}) {
	addr := dcfg.HTTPAddr
	if !isLoopback(addr) {
		log.Warn().Str("addr", addr).Msg("HTTP server bound to non-loopback address — no TLS provided; use a reverse proxy")
	}

	var limiter *rate.Limiter
	if dcfg.TriggerRateLimit > 0 {
		r := rate.Every(time.Minute / time.Duration(dcfg.TriggerRateLimit))
		limiter = rate.NewLimiter(r, dcfg.TriggerRateLimit)
	}

	mux := http.NewServeMux()

	triggerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case triggerCh <- struct{}{}:
		default: // already queued, skip
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.Handle("POST /trigger", authMiddleware(token, rateLimitMiddleware(limiter, triggerHandler)))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		lr := a.lastRenew
		ls := a.lastSync
		a.mu.Unlock()

		resp := map[string]string{"status": "ok"}
		if !lr.IsZero() {
			resp["last_renew"] = lr.Format(time.RFC3339)
		}
		if !ls.IsZero() {
			resp["last_sync"] = ls.Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	if dcfg.MetricsAddr == "" && a.metrics != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(a.metrics.registry, promhttp.HandlerOpts{}))
	}

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Info().Str("addr", addr).Msg("HTTP trigger server listening")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error().Err(err).Msg("HTTP trigger server error")
	}
}

// startServers starts HTTP servers in goroutines tracked by the returned WaitGroup.
// Call wg.Wait() after the daemon loop exits to ensure graceful server shutdown.
func (a *App) startServers(ctx context.Context, dcfg DaemonConfig, token string, triggerCh chan<- struct{}) *sync.WaitGroup {
	var wg sync.WaitGroup
	if dcfg.HTTPAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.startTriggerServer(ctx, dcfg, token, triggerCh)
		}()
	}
	if dcfg.MetricsAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startMetricsServer(ctx, dcfg.MetricsAddr, a)
		}()
	}
	return &wg
}

// RunRenewDaemon runs the renew loop on cfg.Interval, starting immediately.
// POST /trigger (when HTTPAddr set) fires an immediate extra run.
// Exits cleanly on SIGINT/SIGTERM, waiting for HTTP servers to drain.
func (a *App) RunRenewDaemon(cfg RenewConfig) error {
	if err := cfg.DaemonConfig.Validate(); err != nil {
		return err
	}
	if cfg.Buckcert.UserKeyPath == "./le_user.json" {
		return fmt.Errorf("daemon mode requires a persistent LETSENCRYPT_USER_KEY_PATH — " +
			"default './le_user.json' is lost on container restart")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token, err := resolveToken(cfg.HTTPToken, cfg.HTTPTokenFile)
	if err != nil {
		return err
	}

	triggerCh := make(chan struct{}, 1)
	wg := a.startServers(ctx, cfg.DaemonConfig, token, triggerCh)

	log.Info().Dur("interval", cfg.Interval).Msg("renew daemon starting")
	a.Renew(cfg)

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("renew daemon shutting down")
			wg.Wait()
			return nil
		case <-ticker.C:
			a.Renew(cfg)
		case <-triggerCh:
			log.Info().Msg("manual renew triggered via HTTP")
			a.Renew(cfg)
		}
	}
}

// RunSyncDaemon runs the sync loop on cfg.Interval, starting immediately.
// POST /trigger (when HTTPAddr set) fires an immediate extra run.
// Exits cleanly on SIGINT/SIGTERM, waiting for HTTP servers to drain.
func (a *App) RunSyncDaemon(cfg SyncConfig) error {
	if err := cfg.DaemonConfig.Validate(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token, err := resolveToken(cfg.HTTPToken, cfg.HTTPTokenFile)
	if err != nil {
		return err
	}

	triggerCh := make(chan struct{}, 1)
	wg := a.startServers(ctx, cfg.DaemonConfig, token, triggerCh)

	log.Info().Dur("interval", cfg.Interval).Msg("sync daemon starting")
	if err := a.Sync(cfg); err != nil {
		log.Error().Err(err).Msg("initial sync failed")
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("sync daemon shutting down")
			wg.Wait()
			return nil
		case <-ticker.C:
			if err := a.Sync(cfg); err != nil {
				log.Error().Err(err).Msg("sync failed")
			}
		case <-triggerCh:
			log.Info().Msg("manual sync triggered via HTTP")
			if err := a.Sync(cfg); err != nil {
				log.Error().Err(err).Msg("sync failed")
			}
		}
	}
}
