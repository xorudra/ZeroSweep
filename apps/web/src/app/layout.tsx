import type { ReactNode } from "react";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { Shell } from "@/components/Shell";

export const metadata = { title: "DSRclone — Authorized VAPT Platform", description: "GUI-first automated VAPT and security-assessment orchestration platform." };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <Shell>{children}</Shell>
        </AuthProvider>
      </body>
    </html>
  );
}
