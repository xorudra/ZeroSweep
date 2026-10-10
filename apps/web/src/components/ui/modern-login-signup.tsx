"use client";

// Modern login/signup — integrated 2026-10-09 from the supplied
// component, adapted to be DSRclone's REAL auth UI:
// - Three.js comes from the `three` npm package (bundled), not the
//   original's runtime CDN <script> (the app CSP is script-src 'self',
//   which would block cdnjs; a bundled import is also self-contained).
// - The forms are wired to the real API (api.login / api.register via
//   @/lib/api-client) with error + busy states; success stores the
//   token and lands on the console, exactly like the previous page.
// - The Google/GitHub/Apple buttons were REMOVED: DSRclone has no
//   social sign-in, so they could only ever be decorative fakes.
// - Placeholder branding ("JS" logo, "creating a Vercel account"
//   footer) replaced with DSRclone's own.
// - The WebGL dot-grid is decorative: if renderer creation fails the
//   form still works (init is guarded).
import React, { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import * as THREE from "three";
import { api, ApiError, setToken } from "@/lib/api-client";

export default function Component() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    let renderer: THREE.WebGLRenderer | undefined;
    let geometry: THREE.PlaneGeometry | undefined;
    let material: THREE.ShaderMaterial | undefined;
    let animationId = 0;
    let removeResize: (() => void) | undefined;

    try {
      if (!canvasRef.current) return;
      const canvas = canvasRef.current;
      renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: false });
      renderer.setPixelRatio(window.devicePixelRatio);
      renderer.setSize(window.innerWidth, window.innerHeight);

      const scene = new THREE.Scene();
      const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);

      const uniforms = {
        u_time: { value: 0 },
        u_resolution: { value: new THREE.Vector2(window.innerWidth * 2, window.innerHeight * 2) },
        u_opacities: { value: [0.3, 0.3, 0.3, 0.5, 0.5, 0.5, 0.8, 0.8, 0.8, 1.0] },
        u_colors: {
          value: [
            new THREE.Vector3(1, 1, 1),
            new THREE.Vector3(1, 1, 1),
            new THREE.Vector3(1, 1, 1),
            new THREE.Vector3(1, 1, 1),
            new THREE.Vector3(1, 1, 1),
            new THREE.Vector3(1, 1, 1),
          ],
        },
        u_total_size: { value: 20.0 },
        u_dot_size: { value: 6.0 },
        u_reverse: { value: 0 },
      };

      material = new THREE.ShaderMaterial({
        vertexShader: `
          precision mediump float;
          uniform vec2 u_resolution;
          out vec2 fragCoord;
          void main() {
            gl_Position = vec4(position, 1.0);
            fragCoord = (position.xy + 1.0) * 0.5 * u_resolution;
            fragCoord.y = u_resolution.y - fragCoord.y;
          }
        `,
        fragmentShader: `
          precision mediump float;
          in vec2 fragCoord;

          uniform float u_time;
          uniform float u_opacities[10];
          uniform vec3 u_colors[6];
          uniform float u_total_size;
          uniform float u_dot_size;
          uniform vec2 u_resolution;
          uniform int u_reverse;

          out vec4 fragColor;

          float PHI = 1.61803398874989484820459;
          float random(vec2 xy) {
              return fract(tan(distance(xy * PHI, xy) * 0.5) * xy.x);
          }

          void main() {
              vec2 st = fragCoord.xy;
              st.x -= abs(floor((mod(u_resolution.x, u_total_size) - u_dot_size) * 0.5));
              st.y -= abs(floor((mod(u_resolution.y, u_total_size) - u_dot_size) * 0.5));

              float opacity = step(0.0, st.x) * step(0.0, st.y);

              vec2 st2 = vec2(int(st.x / u_total_size), int(st.y / u_total_size));

              float frequency = 5.0;
              float show_offset = random(st2);
              float rand = random(st2 * floor((u_time / frequency) + show_offset + frequency));
              opacity *= u_opacities[int(rand * 10.0)];
              opacity *= 1.0 - step(u_dot_size / u_total_size, fract(st.x / u_total_size));
              opacity *= 1.0 - step(u_dot_size / u_total_size, fract(st.y / u_total_size));

              vec3 color = u_colors[int(show_offset * 6.0)];

              float animation_speed_factor = 3.0;
              vec2 center_grid = u_resolution / 2.0 / u_total_size;
              float dist_from_center = distance(center_grid, st2);

              float timing_offset_intro = dist_from_center * 0.01 + (random(st2) * 0.15);

              float current_timing_offset = timing_offset_intro;
              opacity *= step(current_timing_offset, u_time * animation_speed_factor);
              opacity *= clamp((1.0 - step(current_timing_offset + 0.1, u_time * animation_speed_factor)) * 1.25, 1.0, 1.25);

              fragColor = vec4(color, opacity);
              fragColor.rgb *= fragColor.a;
          }
        `,
        uniforms: uniforms,
        glslVersion: THREE.GLSL3,
        blending: THREE.CustomBlending,
        blendSrc: THREE.SrcAlphaFactor,
        blendDst: THREE.OneFactor,
        transparent: true,
      });

      geometry = new THREE.PlaneGeometry(2, 2);
      const mesh = new THREE.Mesh(geometry, material);
      scene.add(mesh);

      const startTime = performance.now();
      const animate = () => {
        if (!active) return;
        animationId = requestAnimationFrame(animate);
        uniforms.u_time.value = (performance.now() - startTime) / 1000.0;
        renderer?.render(scene, camera);
      };
      animate();

      const handleResize = () => {
        renderer?.setSize(window.innerWidth, window.innerHeight);
        uniforms.u_resolution.value.set(window.innerWidth * 2, window.innerHeight * 2);
      };
      window.addEventListener("resize", handleResize);
      removeResize = () => window.removeEventListener("resize", handleResize);
    } catch {
      // Decorative background only — never let it break the form.
    }

    return () => {
      active = false;
      if (removeResize) removeResize();
      if (animationId) cancelAnimationFrame(animationId);
      if (renderer) renderer.dispose();
      if (geometry) geometry.dispose();
      if (material) material.dispose();
    };
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = isLogin
        ? await api.login(email, password)
        : await api.register(name, email, password, organizationName);
      setToken(res.accessToken);
      router.replace("/");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : isLogin
            ? "Login failed. Is the API running?"
            : "Sign up failed. Is the API running?",
      );
    } finally {
      setBusy(false);
    }
  }

  function switchMode(login: boolean) {
    setIsLogin(login);
    setError(null);
  }

  /* ─── shared input styles (from the supplied design) ─── */
  const input: React.CSSProperties = {
    width: "100%",
    padding: "0.65rem 0.85rem",
    borderRadius: 6,
    border: "1px solid #333",
    background: "#000",
    color: "#fff",
    fontSize: "0.875rem",
    outline: "none",
  };
  const primaryBtn: React.CSSProperties = {
    width: "100%",
    padding: "0.65rem",
    borderRadius: 6,
    border: "none",
    background: "#ededed",
    color: "#000",
    fontWeight: 500,
    fontSize: "0.875rem",
    cursor: "pointer",
    opacity: busy ? 0.6 : 1,
  };
  const toggleBtn: React.CSSProperties = {
    color: "#fff",
    fontWeight: 500,
    background: "none",
    border: "none",
    padding: 0,
    cursor: "pointer",
    fontFamily: "inherit",
    fontSize: "inherit",
  };

  const Logo = (
    <div
      style={{
        background: "#111",
        width: 44,
        height: 44,
        borderRadius: "50%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontWeight: 700,
        fontSize: "1.15rem",
        marginBottom: "0.75rem",
        border: "1px solid #333",
      }}
    >
      DS
    </div>
  );
  const Footer = (
    <div style={{ marginTop: "0.85rem", fontSize: "0.75rem", color: "#666", lineHeight: 1.5, textAlign: "center" }}>
      Authorized VAPT platform — only assess targets you own
      <br />
      or have explicit permission to test.
      <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.9rem", justifyContent: "center", flexWrap: "wrap" }}>
        <Link href="/legal/terms" style={{ color: "#888", textDecoration: "underline" }}>Terms</Link>
        <Link href="/legal/privacy" style={{ color: "#888", textDecoration: "underline" }}>Privacy</Link>
        <Link href="/legal/acceptable-use" style={{ color: "#888", textDecoration: "underline" }}>Acceptable Use</Link>
        <Link href="/legal/security" style={{ color: "#888", textDecoration: "underline" }}>Security</Link>
        <Link href="/legal/subprocessors" style={{ color: "#888", textDecoration: "underline" }}>Subprocessors</Link>
      </div>
    </div>
  );

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        overflow: "hidden",
        background: "#000",
        color: "#fff",
        fontFamily: "'Inter',-apple-system,sans-serif",
      }}
    >
      {/* WebGL dot canvas */}
      <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, zIndex: 0 }} />

      {/* Vignette */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          zIndex: 1,
          background: "radial-gradient(circle at center,rgba(0,0,0,0.75) 0%,rgba(0,0,0,0) 100%)",
          pointerEvents: "none",
        }}
      />

      {/* Card */}
      <div
        style={{
          position: "relative",
          zIndex: 2,
          background: "#121212",
          borderRadius: 12,
          padding: "2rem",
          width: "100%",
          maxWidth: 400,
          boxShadow: "0 10px 40px rgba(0,0,0,0.8)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          border: "1px solid #222",
        }}
      >
        <div style={{ width: "100%", maxWidth: 360, display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}>
          {Logo}
          <h1 style={{ fontSize: "1.35rem", fontWeight: 600, marginBottom: "0.25rem", letterSpacing: "-0.025em" }}>
            {isLogin ? "Sign in to DSRclone" : "Sign up for DSRclone"}
          </h1>
          <p style={{ fontSize: "0.85rem", color: "#888", marginBottom: "0.85rem", lineHeight: 1.5 }}>
            {isLogin ? "Sign in to your account." : "Create a new account to get started."}
          </p>

          <form onSubmit={onSubmit} style={{ width: "100%", display: "flex", flexDirection: "column", gap: "0.65rem" }}>
            {!isLogin && (
              <>
                <input
                  style={input}
                  type="text"
                  placeholder="Full Name"
                  aria-label="Full name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                  required
                />
                <input
                  style={input}
                  type="text"
                  placeholder="Organization Name"
                  aria-label="Organization name"
                  value={organizationName}
                  onChange={(e) => setOrganizationName(e.target.value)}
                  autoComplete="organization"
                  required
                />
              </>
            )}
            <input
              style={input}
              type="email"
              placeholder="name@work-email.com"
              aria-label="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
            <input
              style={input}
              type="password"
              placeholder="Password"
              aria-label="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={isLogin ? "current-password" : "new-password"}
              required
            />
            {error ? (
              <p role="alert" style={{ margin: 0, fontSize: "0.85rem", color: "#fca5a5", textAlign: "left" }}>
                {error}
              </p>
            ) : null}
            <button type="submit" style={primaryBtn} disabled={busy}>
              {isLogin ? (busy ? "Signing in…" : "Sign In") : busy ? "Creating account…" : "Sign Up"}
            </button>
            {!isLogin ? (
              <p style={{ margin: 0, fontSize: "0.75rem", color: "#888", textAlign: "center", lineHeight: 1.5 }}>
                By signing up you agree to the{" "}
                <Link href="/legal/terms" style={{ color: "#bbb", textDecoration: "underline" }}>Terms of Service</Link>
                {" "}and{" "}
                <Link href="/legal/privacy" style={{ color: "#bbb", textDecoration: "underline" }}>Privacy Policy</Link>
                {" "}— and that you will only assess targets you own or are authorized to test.
              </p>
            ) : null}
          </form>

          <div style={{ marginTop: "1.25rem", fontSize: "0.875rem", color: "#888" }}>
            {isLogin ? (
              <>
                Don&rsquo;t have an account?{" "}
                <button type="button" onClick={() => switchMode(false)} style={toggleBtn}>
                  Sign Up
                </button>
              </>
            ) : (
              <>
                Already have an account?{" "}
                <button type="button" onClick={() => switchMode(true)} style={toggleBtn}>
                  Sign In
                </button>
              </>
            )}
          </div>
          {Footer}
        </div>
      </div>
    </div>
  );
}
