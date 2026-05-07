package app

import (
	"github.com/prometheus/client_golang/prometheus"
)

type appMetrics struct {
	registry    *prometheus.Registry
	certExpiry  *prometheus.GaugeVec   // unix seconds; label: domain
	renewTotal  *prometheus.CounterVec // labels: domain, result (ok|fail)
	syncTotal   *prometheus.CounterVec // labels: result (ok|fail)
	lastRenewTs prometheus.Gauge       // unix seconds of last Renew() call
	lastSyncTs  prometheus.Gauge       // unix seconds of last Sync() call
}

func newAppMetrics() *appMetrics {
	reg := prometheus.NewRegistry()

	certExpiry := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tas3_certificate_expiry_seconds",
		Help: "Certificate expiry as a Unix timestamp (seconds).",
	}, []string{"domain"})

	renewTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tas3_renew_total",
		Help: "Total certificate renewal attempts.",
	}, []string{"domain", "result"})

	syncTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tas3_sync_total",
		Help: "Total sync runs.",
	}, []string{"result"})

	lastRenewTs := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tas3_last_renew_timestamp_seconds",
		Help: "Unix timestamp of the last Renew() invocation.",
	})

	lastSyncTs := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tas3_last_sync_timestamp_seconds",
		Help: "Unix timestamp of the last Sync() invocation.",
	})

	reg.MustRegister(certExpiry, renewTotal, syncTotal, lastRenewTs, lastSyncTs)

	return &appMetrics{
		registry:    reg,
		certExpiry:  certExpiry,
		renewTotal:  renewTotal,
		syncTotal:   syncTotal,
		lastRenewTs: lastRenewTs,
		lastSyncTs:  lastSyncTs,
	}
}

// removeDomain cleans up all per-domain metric series so they don't linger after removal.
func (m *appMetrics) removeDomain(domain string) {
	m.certExpiry.DeleteLabelValues(domain)
	m.renewTotal.DeleteLabelValues(domain, "ok")
	m.renewTotal.DeleteLabelValues(domain, "fail")
}
