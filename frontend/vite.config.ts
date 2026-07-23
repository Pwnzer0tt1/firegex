import react from '@vitejs/plugin-react';
import svgrPlugin from 'vite-plugin-svgr';
import { defineConfig } from 'vite';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), svgrPlugin()],
  resolve: {
    tsconfigPaths: true,
  },
})
