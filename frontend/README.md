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
npm run format       # prettier
```

## Layout

```
src/
  app/          routes (App Router), root layout with the theme boot script, globals.css
  components/   UI components built on React Aria
  design/       tokens.css (colours), theme.ts (theme preference logic)
  test/         vitest setup
```

The design spec lives in `plan/design.md` §5. Static export rules: no server-side dynamic routes,
route handlers, cookies or rewrites in production. Use client-side data fetching and query params
for detail views.
