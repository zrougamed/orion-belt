package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Collector holds process-wide counters for Orion Belt.
type Collector struct {
	startTime           time.Time
	SSHSessionsTotal    atomic.Uint64
	SSHSessionsActive   atomic.Int64
	APIRequestsTotal    atomic.Uint64
	AuthFailuresTotal   atomic.Uint64
	AccessRequestsTotal atomic.Uint64
	AgentsConnected     atomic.Int64
}

// Default is the process-wide metrics collector.
var Default = New()

// New creates a metrics collector.
func New() *Collector {
	return &Collector{startTime: time.Now()}
}

// Handler returns an HTTP handler that exposes Prometheus text format.
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		uptime := time.Since(c.startTime).Seconds()
		fmt.Fprintf(w, "# HELP orion_belt_up Orion Belt process up status\n")
		fmt.Fprintf(w, "# TYPE orion_belt_up gauge\n")
		fmt.Fprintf(w, "orion_belt_up 1\n")
		fmt.Fprintf(w, "# HELP orion_belt_uptime_seconds Process uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE orion_belt_uptime_seconds gauge\n")
		fmt.Fprintf(w, "orion_belt_uptime_seconds %.0f\n", uptime)
		fmt.Fprintf(w, "# HELP orion_belt_ssh_sessions_total Total SSH sessions started\n")
		fmt.Fprintf(w, "# TYPE orion_belt_ssh_sessions_total counter\n")
		fmt.Fprintf(w, "orion_belt_ssh_sessions_total %d\n", c.SSHSessionsTotal.Load())
		fmt.Fprintf(w, "# HELP orion_belt_ssh_sessions_active Currently active SSH sessions\n")
		fmt.Fprintf(w, "# TYPE orion_belt_ssh_sessions_active gauge\n")
		fmt.Fprintf(w, "orion_belt_ssh_sessions_active %d\n", c.SSHSessionsActive.Load())
		fmt.Fprintf(w, "# HELP orion_belt_api_requests_total Total API HTTP requests\n")
		fmt.Fprintf(w, "# TYPE orion_belt_api_requests_total counter\n")
		fmt.Fprintf(w, "orion_belt_api_requests_total %d\n", c.APIRequestsTotal.Load())
		fmt.Fprintf(w, "# HELP orion_belt_auth_failures_total Authentication failures\n")
		fmt.Fprintf(w, "# TYPE orion_belt_auth_failures_total counter\n")
		fmt.Fprintf(w, "orion_belt_auth_failures_total %d\n", c.AuthFailuresTotal.Load())
		fmt.Fprintf(w, "# HELP orion_belt_access_requests_total Access requests created\n")
		fmt.Fprintf(w, "# TYPE orion_belt_access_requests_total counter\n")
		fmt.Fprintf(w, "orion_belt_access_requests_total %d\n", c.AccessRequestsTotal.Load())
		fmt.Fprintf(w, "# HELP orion_belt_agents_connected Connected agents\n")
		fmt.Fprintf(w, "# TYPE orion_belt_agents_connected gauge\n")
		fmt.Fprintf(w, "orion_belt_agents_connected %d\n", c.AgentsConnected.Load())
	})
}

// IncAPIRequest increments the API request counter.
func (c *Collector) IncAPIRequest() { c.APIRequestsTotal.Add(1) }

// IncAuthFailure increments auth failure counter.
func (c *Collector) IncAuthFailure() { c.AuthFailuresTotal.Add(1) }

// IncAccessRequest increments access request counter.
func (c *Collector) IncAccessRequest() { c.AccessRequestsTotal.Add(1) }

// SessionStarted records a new SSH session.
func (c *Collector) SessionStarted() {
	c.SSHSessionsTotal.Add(1)
	c.SSHSessionsActive.Add(1)
}

// SessionEnded records an ended SSH session.
func (c *Collector) SessionEnded() {
	c.SSHSessionsActive.Add(-1)
}

// SetAgentsConnected sets the connected agent gauge.
func (c *Collector) SetAgentsConnected(n int64) {
	c.AgentsConnected.Store(n)
}
