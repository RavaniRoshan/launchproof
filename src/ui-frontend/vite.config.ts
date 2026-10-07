import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// Builds a static bundle the LaunchProof daemon serves at `/` (no frontend
// server in production; the daemon is the only process).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  server: {
    // Dev-only proxy to a running daemon; production talks same-origin.
    proxy: {
      '/api': 'http://127.0.0.1:4821',
      '/health': 'http://127.0.0.1:4821',
    },
  },
  build: {
    outDir: path.resolve(__dirname, '../ui/dist'),
    emptyOutDir: true,
    target: 'es2022',
  },
} as Parameters<typeof defineConfig>[0] & { server: { proxy: Record<string, string> } })
