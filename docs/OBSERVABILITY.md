# Observability

Shipped with **v0.9.0**. Orion Belt emits **structured JSON logs** (stdout via `log/slog`), **Prometheus metrics** at `/metrics`, and request-scoped `request_id` fields for correlation. Full OpenTelemetry span export is staged for a later release; use logs + metrics for Loki/ELK and alerting today.

## Structured logs (Loki / ELK)

Gateway logs are one JSON object per line on stdout. Typical fields:

| Field | Meaning |
|-------|---------|
| `time`, `level`, `msg` | slog defaults |
| `request_id` | Per-HTTP request correlation (middleware) |
| caller attrs | Component-specific keys from logger wrappers |

### Promtail / Alloy → Loki (sketch)

```yaml
scrape_configs:
  - job_name: orion-belt
    static_configs:
      - targets: [localhost]
        labels:
          job: orion-belt
          __path__: /var/log/orion-belt/*.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            msg: msg
            request_id: request_id
      - labels:
          level:
          request_id:
```

For journald-backed units, scrape the `orion-belt-server` unit and parse JSON message payload the same way.

### Elasticsearch

Ship the same JSON lines with Filebeat `json.keys_under_root: true` (or Elastic Agent log integration). Index on `request_id`, `level`, and message keywords such as `access.request` / `auth`.

## Prometheus metrics

Enable the metrics listener (see `docs/SETUP.md` / server config). Scrape `/metrics` for gauges and counters including:

- `orion_belt_up`
- `orion_belt_uptime_seconds`
- `orion_belt_ssh_sessions_total` / `orion_belt_ssh_sessions_active`
- `orion_belt_api_requests_total`
- `orion_belt_auth_failures_total`
- `orion_belt_access_requests_total`
- `orion_belt_agents_connected`

## Example alert rules

Save as `deploy/prometheus/orion-belt-alerts.yml` or merge into your Prometheus rule groups:

```yaml
groups:
  - name: orion-belt
    rules:
      - alert: OrionBeltDown
        expr: absent(orion_belt_up) or orion_belt_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: Orion Belt gateway is down or unscrapeable

      - alert: OrionBeltAuthFailuresHigh
        expr: increase(orion_belt_auth_failures_total[15m]) > 50
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Elevated authentication failures

      - alert: OrionBeltNoAgents
        expr: orion_belt_agents_connected == 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: No agents connected to the gateway

      - alert: OrionBeltSessionsStuck
        expr: orion_belt_ssh_sessions_active > 100
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: Unusually high active SSH session count
```

Wire Alertmanager (or Grafana Alerting) to page on `critical` and notify ops chat on `warning`.


