## What and why

<!-- One or two sentences. Reference the audit ID if this resolves one, e.g. (DET-01). -->

## How it was checked

- [ ] Backend: `uv run ruff check . && uv run mypy && uv run pytest` (in `backend/`)
- [ ] Frontend: `npm run lint && npm run typecheck && npm test` (in `frontend/`)
- [ ] API changed: regenerated `frontend/openapi.json` and `src/lib/api/schema.d.ts`
- [ ] UI changed: checked in light and dark, and with the keyboard only
- [ ] ML changed: numbers come from `nids evaluate`, and `docs/model-card.md` is updated
- [ ] Docs or ADRs updated where behaviour changed
