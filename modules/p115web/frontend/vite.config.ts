import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";
import svgr from "vite-plugin-svgr";
import tailwindcssNesting from "tailwindcss/nesting";
import postcssImport from "postcss-import";

function pathResolve(dir: string) {
  return resolve(process.cwd(), ".", dir);
}

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  process.env = { ...process.env, ...loadEnv(mode, process.cwd()) };

  return {
    root: "./",
    base: "/",
    publicDir: "public",
    plugins: [svgr(), react()],
    resolve: {
      alias: [
        {
          find: /\/@\//,
          replacement: pathResolve("src") + "/",
        },
      ],
    },
    server: {
      host: true,
      port: 3000,
      // open: true,
      proxy: {
        "/api": {
          target: process.env.VITE_API_URL,
          changeOrigin: true,
          secure: false,
        },
        "/ws": {
          target: "ws://127.0.0.1",
          ws: true,
        },
      },
    },
    build: {
      target: "es2015",
      cssTarget: "chrome80",
      outDir: "dist",
    },
    css: {
      postcss: {
        plugins: [postcssImport, tailwindcssNesting, tailwindcss, autoprefixer],
      },
    },
  };
});
