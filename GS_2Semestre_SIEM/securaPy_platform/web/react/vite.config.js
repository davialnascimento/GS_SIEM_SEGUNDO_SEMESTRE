const headersDevE = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  // Em desenvolvimento, Vite/React Refresh precisa permitir scripts inline.
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: http://127.0.0.1:8001; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
};
const headersPreviewE = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
};

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  // VIOTRACE_MODULOS_E_G_V1
  plugins: [react()],
  server: {
    headers: headersDevE,
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": "http://127.0.0.1:8001" },
  },
  preview: { headers: headersPreviewE },
});
