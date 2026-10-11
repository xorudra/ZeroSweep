import Link from "next/link";

/**
 * Launch Safety H39: a useful 404. Next's built-in fallback is a bare
 * unbranded page with no way back into the console; this keeps the
 * user oriented (what happened, where to go) in the product's own
 * chrome language.
 */
export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 py-16 text-slate-100">
      <div className="w-full max-w-md text-center">
        <p className="text-sm font-semibold uppercase tracking-widest text-slate-400">404</p>
        <h1 className="mt-3 text-3xl font-bold">This page doesn&apos;t exist</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          The link may be broken, or the page may have been moved or deleted.
          Nothing was changed by visiting it.
        </p>
        <div className="mt-8 flex items-center justify-center gap-3">
          <Link
            href="/dashboard"
            className="rounded-lg bg-white px-5 py-2.5 text-sm font-medium text-slate-900 hover:bg-slate-200"
          >
            Go to dashboard
          </Link>
          <Link
            href="/legal/privacy"
            className="rounded-lg border border-slate-700 px-5 py-2.5 text-sm font-medium text-slate-200 hover:bg-slate-900"
          >
            Privacy
          </Link>
        </div>
      </div>
    </main>
  );
}
