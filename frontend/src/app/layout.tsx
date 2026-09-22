import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";

import { THEME_BOOT_SCRIPT } from "@/design/theme";
import { Providers } from "@/lib/providers";

import "./globals.css";

// Downloaded at build time and self-hosted; no requests to Google at runtime.
const plexSans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "AI-NIDS", template: "%s · AI-NIDS" },
  description: "Flow-based network intrusion detection",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // data-theme is set by the boot script before paint, so the server markup can differ.
    <html
      lang="en"
      data-theme="light"
      suppressHydrationWarning
      className={`${plexSans.variable} ${plexMono.variable}`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body className="min-h-dvh bg-bg text-ink">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
