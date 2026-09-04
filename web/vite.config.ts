import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The FastAPI server (ecdat serve) mounts the built app at / and the API at /api.
// In dev, proxy /api to the local server so the app can use relative URLs in both modes.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5181,
    proxy: { '/api': { target: 'http://127.0.0.1:8787', changeOrigin: true } },
  },
  build: { outDir: 'dist', sourcemap: false },
})
