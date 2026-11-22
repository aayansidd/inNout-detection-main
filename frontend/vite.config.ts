import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// The dev proxy follows VITE_BACKEND_PORT (default 8000); keep it equal to AEGIS_PORT.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const port = env.VITE_BACKEND_PORT || "8000";
  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      strictPort: true, // the API only accepts the 5173 origin; never drift to another port
      proxy: {
        "/api": `http://127.0.0.1:${port}`,
        "/ws": { target: `ws://127.0.0.1:${port}`, ws: true },
      },
    },
  };
});
