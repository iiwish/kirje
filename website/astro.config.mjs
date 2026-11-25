import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://kirje.app',
  base: '/',
  vite: {
    plugins: [tailwindcss()],
  },
});
