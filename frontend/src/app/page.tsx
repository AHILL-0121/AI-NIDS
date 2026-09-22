import { ThemeToggle } from "@/components/ThemeToggle";

// Placeholder until the app shell lands (plan/checklist.md, Phase 7).
// It shows the brand, the theme toggle and the token palette so both themes can be checked.

const SEVERITIES = [
  { label: "Critical", fg: "text-sev-critical", wash: "bg-[var(--sev-critical-wash)]" },
  { label: "High", fg: "text-sev-high", wash: "bg-[var(--sev-high-wash)]" },
  { label: "Medium", fg: "text-sev-medium", wash: "bg-[var(--sev-medium-wash)]" },
  { label: "Low", fg: "text-sev-low", wash: "bg-[var(--sev-low-wash)]" },
] as const;

function SonarMark() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden className="text-ink">
      <circle cx="4" cy="16" r="1.75" fill="currentColor" />
      <path d="M4 10.5a5.5 5.5 0 0 1 5.5 5.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M4 6.5a9.5 9.5 0 0 1 9.5 9.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M4 2.5A13.5 13.5 0 0 1 17.5 16" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export default function Home() {
  return (
    <div className="mx-auto flex min-h-dvh max-w-3xl flex-col px-4 py-8 sm:px-8">
      <header className="flex items-center justify-between border-b border-line pb-4">
        <div className="flex items-center gap-2">
          <SonarMark />
          <span className="text-section font-semibold tracking-tight">AI-NIDS</span>
          <span className="font-mono text-meta text-ink-subtle">v2 · scaffold</span>
        </div>
        <ThemeToggle />
      </header>

      <main className="flex flex-1 flex-col gap-8 py-10">
        <section className="flex flex-col gap-2">
          <p className="text-label font-medium text-ink-subtle uppercase">Status</p>
          <h1 className="text-page font-semibold">The frontend is set up. Screens come next.</h1>
          <p className="max-w-prose text-ink-muted">
            Next.js static export, React Aria primitives and the Signal Paper tokens. Switch the
            theme above to check both palettes.
          </p>
        </section>

        <section
          aria-labelledby="severity-heading"
          className="rounded-[var(--radius-panel)] border border-line bg-surface"
        >
          <h2
            id="severity-heading"
            className="border-b border-line px-4 py-2 text-label font-medium text-ink-subtle uppercase"
          >
            Severity scale
          </h2>
          <ul className="flex flex-wrap gap-2 p-4">
            {SEVERITIES.map(({ label, fg, wash }) => (
              <li
                key={label}
                className={`rounded-[var(--radius-control)] px-2 py-0.5 text-meta font-medium ${fg} ${wash}`}
              >
                {label}
              </li>
            ))}
          </ul>
          <dl className="grid grid-cols-2 border-t border-line font-mono text-dense sm:grid-cols-4">
            {[
              ["src", "10.0.0.23"],
              ["dst", "10.0.0.1:443"],
              ["flows/s", "212"],
              ["drops", "0.00 %"],
            ].map(([term, value]) => (
              <div key={term} className="border-line px-4 py-3 not-last:border-r">
                <dt className="font-sans text-label text-ink-subtle uppercase">{term}</dt>
                <dd className="tabular-nums">{value}</dd>
              </div>
            ))}
          </dl>
        </section>
      </main>
    </div>
  );
}
