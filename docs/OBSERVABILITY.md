# Observability

JSON logs on stdout, Prometheus text at `/metrics`, and a `request_id` on HTTP requests so you can glue events together. There’s no OTLP tracing exporter yet — ship logs to Loki/ELK (or whatever you use) and scrape metrics for alerts.

## Logs → Loki / ELK

One JSON object per line. You’ll usually see `time`, `level`, `msg`, and often `request_id`.

### Promtail / Alloy sketch

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

If you run under systemd, scrape the `orion-belt-server` unit and parse the JSON payload the same way.

### Elasticsearch

Filebeat with `json.keys_under_root: true` (or the Elastic Agent equivalent) is enough. Indexing on `request_id` and `level` helps.

## Metrics

Scrape `/metrics`. Counters/gauges include:

- `orion_belt_up`
- `orion_belt_uptime_seconds`
- `orion_belt_ssh_sessions_total` / `orion_belt_ssh_sessions_active`
- `orion_belt_api_requests_total`
- `orion_belt_auth_failures_total`
- `orion_belt_access_requests_total`
- `orion_belt_agents_connected`

## Operational dashboard snapshot API

For day-to-day operational visibility in the console, Orion Belt exposes a rolling analytics snapshot at:

- `GET /api/v1/dashboard/usage?window_hours=24&top=5`

It returns access volume, approval latency (avg/p50/p95), and most-accessed targets for the requested window. The web dashboard polls this endpoint periodically, so operators do not need to generate a report manually.

## Example alerts

Drop-in file: `deploy/prometheus/orion-belt-alerts.yml` — down instance, auth failure spike, no agents, silly number of active sessions. Point Alertmanager (or Grafana) at whatever you already use.


