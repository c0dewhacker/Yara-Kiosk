import { defineConfig } from "vite";

export default defineConfig({
  root: "src",
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  worker: {
    format: "es",
  },
  optimizeDeps: {
    exclude: ["@virustotal/yara-x"],
  },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    // Monaco workers require at least chrome80; yara-x WASM requires chrome89+.
    target: "chrome105",
    minify: !process.env.TAURI_ENV_DEBUG ? ("oxc" as const) : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
});
