import { LinkButton } from "@/components/Button";
import { SonarMark } from "@/components/Brand";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-sm flex-col items-start justify-center gap-3 px-4">
      <SonarMark size={28} />
      <h1 className="text-page font-semibold">Page not found</h1>
      <p className="text-ink-muted">There’s nothing at this address.</p>
      <LinkButton href="/" variant="primary">
        Go to Overview
      </LinkButton>
    </main>
  );
}
