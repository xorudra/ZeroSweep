"use client";

/**
 * Launch Safety H39: a render error in one screen must not strand the
 * user on Next's default error page. This boundary names what happened
 * in plain words and offers the standard recovery — retry the render
 * in place (reset, which keeps the signed-in session) or fall back to
 * the dashboard via a plain anchor (deliberate: it still works even
 * if client routing is what broke; it reloads the app, and because
 * sign-in tokens are memory-only the user is asked to sign in again —
 * the copy below says exactly that).
 */
export default function AppError({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 py-16 text-slate-100">
      <div className="w-full max-w-md text-center">
        <p className="text-sm font-semibold uppercase tracking-widest text-slate-400">Something went wrong</p>
        <h1 className="mt-3 text-3xl font-bold">This screen hit an error</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          The rest of ZeroSweep is unaffected, and no data was changed.
          Try showing this screen again — that keeps you signed in. If it
          keeps failing, the dashboard button reloads the app and will
          ask you to sign in again.
        </p>
        <div className="mt-8 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => reset()}
            className="rounded-lg bg-white px-5 py-2.5 text-sm font-medium text-slate-900 hover:bg-slate-200"
          >
            Try again
          </button>
          <a
            href="/dashboard"
            className="rounded-lg border border-slate-700 px-5 py-2.5 text-sm font-medium text-slate-200 hover:bg-slate-900"
          >
            Go to dashboard
          </a>
        </div>
      </div>
    </main>
  );
}
