# AI-NIDS frontend

Next.js (App Router) built as a **static export** that the FastAPI backend serves. React Aria
Components for accessible primitives, Tailwind v4 with the "Signal Paper" design tokens, and
light/dark/system theming.

## Commands

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000, with /api/* proxied to the backend (NIDS_BACKEND_URL, default http://localhost:8000)
npm run build        # static export to out/
npm run lint
npm run typecheck
npm test             # vitest
npm run test:coverage  # vitest with the components >= 70 % gate
npm run format       # prettier
npm run e2e          # build, then Playwright against the real backend (see below)
```

## End-to-end and accessibility tests

`npm run e2e` builds the UI, starts `uv run nids api` from `../backend` on port 8766 with a fresh
temporary database, and runs `tests/e2e/` in a real browser (the installed Microsoft Edge on
Windows; elsewhere run `npx playwright install chromium` once):

1. `setup.e2e.ts`: the first-run wizard, through the UI.
2. `flow.e2e.ts`: upload and replay the nmap fixture capture, see the port-scan alert arrive live
   over the WebSocket, acknowledge it, generate the session report and download its PDF.
3. `a11y.e2e.ts`: axe (WCAG 2.2 AA) on every page, in light and dark, with real data on screen.

`npm run e2e:only` skips the build.

## Layout

```
src/
  app/          routes (App Router), root layout with the theme boot script, globals.css
  components/   UI components built on React Aria
  design/       tokens.css (colours), theme.ts (theme preference logic)
  test/         vitest setup
tests/e2e/      Playwright specs (full stack)
```

The design spec lives in `plan/design.md` §5. Static export rules: no server-side dynamic routes,
route handlers, cookies or rewrites in production. Use client-side data fetching and query params
for detail views.
