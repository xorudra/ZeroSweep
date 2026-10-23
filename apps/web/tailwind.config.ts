import type { Config } from "tailwindcss";

/**
 * Design system — "True-black flat" (taste-skill app sheet, seed
 * 2134747149, dealt 2026-10-23; owner order: rebuild the UI with the
 * taste + impeccable skills). One ground #000, surfaces by lightness
 * step alone (#111 card, #2a2a2a raised), no navy/slate anywhere,
 * colour only on data and status. The slate scale is REMAPPED onto
 * the neutral scale so every existing slate-* class renders the new
 * world: 950 ground, 900 surface, 800 rule/border, 700 raised,
 * 600 control edge, 500 icon grey, 400 meta, 300 secondary, 100-50 ink.
 */
export default {
  content: ["./src/**/*.{ts,tsx}", "../../packages/ui/src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        slate: {
          50: "#ffffff",
          100: "#f5f5f5",
          200: "#e6e6e6",
          300: "#b4b4b4",
          400: "#949494",
          500: "#6b6b6b",
          600: "#444444",
          700: "#2a2a2a",
          800: "#1a1a1a",
          900: "#111111",
          950: "#000000",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
      },
      borderRadius: {
        sm: "6px",
        DEFAULT: "8px",
        md: "8px",
        lg: "12px",
        xl: "20px",
        "2xl": "24px",
        "3xl": "28px",
      },
      boxShadow: {
        sm: "none",
        DEFAULT: "none",
        md: "none",
        lg: "0 12px 32px rgba(0,0,0,0.5)",
        xl: "0 16px 40px rgba(0,0,0,0.55)",
        "2xl": "0 24px 48px rgba(0,0,0,0.6)",
        inner: "none",
        none: "none",
      },
    },
  },
  plugins: [],
} satisfies Config;
