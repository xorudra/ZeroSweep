import type { ReactNode } from "react";
import { headers } from "next/headers";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { Shell } from "@/components/Shell";

export const metadata = { title: "ZeroSweep — Authorized VAPT Platform", description: "GUI-first automated VAPT and security-assessment orchestration platform." };

export default function RootLayout({ children }: { children: ReactNode }) {
  // The middleware stamps the request with its auth verdict so the very
  // first server paint is already the right page — no spinner, no flash.
  const verdict = headers().get("x-zs-auth");
  const initialAuth = verdict === "valid" || verdict === "anon" ? verdict : null;
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body>
        <AuthProvider initialAuth={initialAuth}>
          <Shell>{children}</Shell>
        </AuthProvider>
      </body>
    </html>
  );
}
