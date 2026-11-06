import { defineConfig } from 'vite';

// Served from GitHub Pages at https://alan021011.github.io/near-policy-vault/
export default defineConfig({
  base: process.env.PAGES_BASE ?? '/near-policy-vault/',
  build: { target: 'es2022' },
});
