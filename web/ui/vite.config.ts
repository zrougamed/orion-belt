import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const gateway = process.env.ORION_GATEWAY || "http://127.0.0.1:8080";

// Builds into web/static for go:embed (served at /ui/).
export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Explicit ws:true — shorthand targets often drop terminal WebSocket upgrades.
      "/api": {
        target: gateway,
        changeOrigin: true,
        ws: true,
        secure: false,
      },
      "/health": {
        target: gateway,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: path.resolve(__dirname, "../static"),
    emptyOutDir: true,
    sourcemap: true,
  },
});
