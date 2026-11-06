import Link from "next/link";
import "./landing.css";

/**
 * Public landing — v7 preview (owner-approved 2026-11-06, "Deploy v7").
 * Renders only for signed-out visitors at /; signed-in visitors see the
 * Overview instead (see app/page.tsx). The dashboard cards show
 * illustrative sample UI exactly as in the approved preview — they are
 * not live data.
 *
 * Links: Sign in -> /login, Start free -> /invite (invite-only entry).
 * "Run the free check" -> /login for now: no public check page exists
 * yet, checks run inside after sign-in. Pricing / Docs / Changelog
 * keep the preview's placeholder links — those pages do not exist yet.
 */
export function LandingPage() {
  return (
    <div className="zs-landing">
      <div className="nav">
        <div className="logo">
          <img className="logo-img" src="/zerosweep-logo.png" alt="ZeroSweep logo" width={30} height={30} />
          ZeroSweep
        </div>
        <div className="nav-menu">
          <a href="#features">Features</a>
          <a href="#scans">Scans</a>
          <a href="#">Pricing</a>
          <a href="#">Docs</a>
          <a href="#">Changelog</a>
        </div>
        <div className="nav-links">
          <Link className="signin" href="/login">Sign in</Link>
          <Link className="cta-small" href="/invite">Start free</Link>
        </div>
      </div>

      <div className="hero">
        <h1>
          Find the <em>holes</em>
          <br />
          before attackers do.
        </h1>
        <p className="sub">GUI-first vulnerability testing across 100+ tools. Scans run only on targets you own and approve — no exceptions, no noise.</p>
        <div className="ctas">
          <Link className="cta-fill" href="/login">Run the free check</Link>
          <a className="cta-ghost" href="#how">See how it works</a>
        </div>
        <p className="free-note"><b>FREE</b> TLS &amp; headers check — no ownership proof needed.</p>
      </div>

      <div className="cards" id="scans">
        <div className="card">
          <div className="label"><i />Findings</div>
          <div className="finding"><div className="f-name">SQL injection — login form<small>Verified · Web scan</small></div><span className="chip crit">Critical</span></div>
          <div className="finding"><div className="f-name">Exposed .env — staging<small>Verified · Config scan</small></div><span className="chip high">High</span></div>
          <div className="finding"><div className="f-name">Missing CSP header<small>Candidate · Headers</small></div><span className="chip med">Medium</span></div>
          <div className="finding"><div className="f-name">TLS 1.0 still enabled<small>Verified · Network</small></div><span className="chip med">Low</span></div>
        </div>

        <div className="card glow">
          <div className="label"><i />Security posture</div>
          <div className="score"><b>87</b><span>/ 100 target health</span><span className="chip crit">Verified only</span></div>
          <svg viewBox="0 0 320 90" width="100%" height="90" style={{ marginTop: 8 }} aria-hidden>
            <polyline points="0,78 35,70 70,74 105,60 140,64 175,48 210,52 245,34 280,40 320,18" fill="none" stroke="#0B0B0C" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
            <line x1="0" y1="78" x2="320" y2="78" stroke="rgba(11,11,12,.15)" strokeWidth="1" />
          </svg>
        </div>

        <div className="card">
          <div className="label"><i />Live scans</div>
          <div className="scan"><div className="s-top"><div className="f-name">Web comprehensive<small>zerosweep.io · 100+ tools</small></div><span className="chip crit">Running</span></div><div className="progress"><i style={{ width: "72%" }} /></div></div>
          <div className="scan"><div className="s-top"><div className="f-name">Network sweep<small>10.0.0.0/24 · Ports + services</small></div><span className="chip crit">Running</span></div><div className="progress"><i style={{ width: "45%" }} /></div></div>
          <div className="scan"><div className="s-top"><div className="f-name">Cloud config<small>AWS prod · Misconfig check</small></div><span className="chip high">Done</span></div><div className="progress"><i style={{ width: "100%" }} /></div></div>
          <div className="scan"><div className="s-top"><div className="f-name">Code review<small>api-service · SAST</small></div><span className="chip med">Queued</span></div><div className="progress"><i style={{ width: "0%" }} /></div></div>
        </div>
      </div>

      <div className="stats">
        <div className="stat"><b>100+</b><span>Security tools</span></div>
        <div className="stat"><b>40/40</b><span>Phases shipped</span></div>
        <div className="stat"><b>Invite-only</b><span>Access</span></div>
        <div className="stat"><b>Verified only</b><span>Targets scanned</span></div>
      </div>

      <div className="section" id="features">
        <h2>Built for real assessments</h2>
        <div className="feat-grid">
          <div className="feat"><span className="mark" /><b>Verified targets only</b><p>Every scan starts with proof you own the target and a recorded approval. Unverified targets are refused.</p></div>
          <div className="feat"><span className="mark" /><b>100+ tools, one report</b><p>Web, network, cloud, containers and code — normalized into a single findings view you can act on.</p></div>
          <div className="feat"><span className="mark" /><b>Findings, not noise</b><p>Candidates are candidates until verified. No placeholder vulnerabilities, no inflated counts.</p></div>
        </div>
      </div>

      <div className="dark" id="how">
        <h2>How it works</h2>
        <div className="steps-grid">
          <div className="step"><div className="n">1</div><div><b>Verify your target</b><p>Prove ownership with a DNS record or a file on the server.</p></div></div>
          <div className="step"><div className="n">2</div><div><b>Approve the scope</b><p>Define exactly what is in scope. The approval is recorded.</p></div></div>
          <div className="step"><div className="n">3</div><div><b>Get the findings</b><p>Real engines, real results — ranked by what matters most.</p></div></div>
        </div>
      </div>

      <div className="footer">
        <div className="logo">
          <img className="logo-img" src="/zerosweep-logo.png" alt="ZeroSweep logo" width={30} height={30} />
          ZeroSweep
        </div>
        <p>Automated vulnerability assessment, built for owners who want proof — not promises.</p>
        <span className="invite">INVITE-ONLY</span>
      </div>

      <div className="swatches">
        <div className="sw ink"><span className="tag">60%</span><b>Midnight<br />Black</b><hr /><code>#0B0B0C</code></div>
        <div className="sw white"><span className="tag">40%</span><b>Soft<br />Ivory</b><hr /><code>#FAF8F3</code></div>
        <div className="sw lime"><span className="tag">Accent</span><b>Silver<br />Gradient</b><hr /><code>from the logo</code></div>
      </div>
    </div>
  );
}
