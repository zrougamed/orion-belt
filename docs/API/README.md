# Orion Belt HTTP API

Canonical OpenAPI 3.0 specification:

- **Source:** [../openapi/openapi.yaml](../openapi/openapi.yaml)
- **Live (running server):** `GET /api/v1/openapi.yaml`
- **Postman:** [postman_collection.json](postman_collection.json) · [postman_env.json](postman_env.json)

## Browse with Swagger UI

```bash
# Against a running gateway
docker run --rm -p 8090:8080 \
  -e SWAGGER_JSON_URL=http://host.docker.internal:8080/api/v1/openapi.yaml \
  swaggerapi/swagger-ui
# open http://localhost:8090
```

Or locally without Docker:

```bash
npx @redocly/cli preview-docs docs/openapi/openapi.yaml
# or
npx swagger-ui-watcher docs/openapi/openapi.yaml
```

## Auth quick reference

| Mechanism | Header / cookie / query |
|-----------|-------------------------|
| API key | `X-API-Key: <key>` |
| Session | `X-Session-Token` or cookie `session_token` or `?token=` |
| JWT | `Authorization: Bearer <jwt>` |

Admin routes under `/api/v1/admin/*` require role **admin** or **operator**.

## Related docs

- [SRS-UI.md](../SRS-UI.md) — web console requirements (as implemented)
- [ARCHITECTURE.md](../ARCHITECTURE.md)
- [PACKAGING.md](../PACKAGING.md)
