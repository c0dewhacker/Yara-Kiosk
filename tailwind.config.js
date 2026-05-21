/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{html,ts}"],
  theme: {
    extend: {
      colors: {
        // YARA-X website palette
        surface: {
          950: "#0f0f1e",   // deeper than body bg, for outer shell
          900: "#161625",   // body bg (#161625 from yarax dark mode)
          800: "#1e1e32",   // card backgrounds
          700: "#252540",   // elevated surfaces
          600: "#2e2e50",   // borders, dividers
          500: "#414349",   // muted / dot colour
        },
        primary: {
          DEFAULT: "#86aaf9",   // yarax dark-mode btn-primary bg
          hover:   "#98b7fa",
          light:   "#b8ccfc",
          muted:   "#5a7bd4",
        },
        // Signature YARA-X gradient stops
        grad: {
          from: "#009efd",  // blue start
          to:   "#2af598",  // teal-green end
        },
        success: "#84ee53",   // yarax --bs-success (bright lime, "clean")
        danger:  "#ee5389",   // yarax --bs-danger  (pink-red, "threat")
        warning: "#eebd53",   // yarax --bs-warning (amber)
        info:    "#3347ff",   // yarax --bs-info    (vivid blue)
      },
      fontFamily: {
        // Jost is the YARA-X site font; fallback to system sans
        sans: ["Jost", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["SFMono-Regular", "Menlo", "Monaco", "Consolas", "Liberation Mono", "Courier New", "monospace"],
      },
      backgroundImage: {
        // YARA-X signature gradient (used on logo, CTAs)
        "yarax-gradient": "linear-gradient(90deg, #009efd 0%, #2af598 100%)",
        // Dot-grid texture (matches yarax bg-dots in dark mode)
        "dot-grid": "radial-gradient(#414349 15%, transparent 15%)",
      },
    },
  },
  plugins: [],
};
