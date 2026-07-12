# Orion Belt web console (React)

Source for the privileged-access UI. Production assets are built into
`../static/` and embedded by the Go server at `/ui/`.

## Develop

```bash
# Terminal A — API (lab or local server) on :8080
# Terminal B
cd web/ui
npm install
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8080`. Open the printed local URL
(usually `http://127.0.0.1:5173/ui/`).

## Production build

```bash
make build-ui
# or
cd web/ui && npm run build
```

Then rebuild the server so `go:embed` picks up `web/static`.

## Stack

- Vite + React 19 + TypeScript
- React Router, TanStack Query
- xterm.js for live terminal and cast playback
- Orion theme tokens in `src/styles/theme.css`
