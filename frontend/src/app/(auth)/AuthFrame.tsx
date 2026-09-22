import type { ReactNode } from "react";

import { SonarMark } from "@/components/Brand";
import { ThemeToggle } from "@/components/ThemeToggle";

/** Centred single-column frame for sign-in and first-run setup. */
export function AuthFrame({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="flex items-center justify-between px-4 py-3 sm:px-6">
        <div className="flex items-center gap-2">
          <SonarMark />
          <span className="text-section font-semibold tracking-tight">AI-NIDS</span>
        </div>
        <ThemeToggle />
      </header>
      <main
        className={`mx-auto w-full flex-1 px-4 pt-[8vh] pb-12 ${wide ? "max-w-[560px]" : "max-w-sm"}`}
      >
        {children}
      </main>
    </div>
  );
}
