# SentinelForge UI

React dashboard for the SentinelForge API. Vite builds the app. The cyberpunk layout lives in `src/styles.css`, split across search, table, detail, submit, and stats components.

```bash
npm ci
npm start
```

`VITE_API_BASE` defaults to `http://127.0.0.1:8080`. `VITE_API_KEY` is sent as `X-API-Key` when it is set. Both can come from the repo-root `.env` when you build through Docker Compose.

```bash
npm run lint
npm test
npm run build
```
