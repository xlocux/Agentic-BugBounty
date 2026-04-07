import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  build: {
    outDir:      "../ui/dist",
    emptyOutDir: true
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target:       "http://127.0.0.1:31337",
        changeOrigin: true
      }
    }
  }
});
