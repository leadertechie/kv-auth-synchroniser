import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'KVAuthSynchroniser',
      fileName: 'index',
      formats: ['es'],
    },
    rollupOptions: {
      external: [
        // Add any external dependencies here
      ],
      output: {
        globals: {
          // Add any globals here
        },
      },
    },
    sourcemap: true,
    minify: false,
  },
  plugins: [
    dts({
      insertTypesEntry: true,
      include: ['src/**/*.ts'],
    }),
  ],
});
