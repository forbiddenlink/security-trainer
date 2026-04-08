import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("/src/data/modules/")) {
            return "lesson-content";
          }

          if (
            id.includes("/node_modules/monaco-editor/") ||
            id.includes("/node_modules/@monaco-editor/")
          ) {
            return "monaco-vendor";
          }

          if (id.includes("/node_modules/framer-motion/")) {
            return "motion-vendor";
          }

          if (
            id.includes("/node_modules/react-router/") ||
            id.includes("/node_modules/react-router-dom/")
          ) {
            return "router-vendor";
          }

          if (
            id.includes("/node_modules/react/") ||
            id.includes("/node_modules/react-dom/") ||
            id.includes("/node_modules/scheduler/")
          ) {
            return "react-vendor";
          }

          if (
            id.includes("/node_modules/react-markdown/") ||
            id.includes("/node_modules/unified/") ||
            id.includes("/node_modules/remark-") ||
            id.includes("/node_modules/rehype-")
          ) {
            return "markdown-vendor";
          }

          if (id.includes("/node_modules/lucide-react/")) {
            return "icons-vendor";
          }

          // Mermaid and its large dependencies (D3, etc.) - loaded on demand
          // NOTE: dompurify is intentionally excluded here because posthog-js
          // also depends on it, which would force the entire mermaid chunk to
          // load eagerly at startup and cause a runtime crash.
          if (
            id.includes("/node_modules/mermaid/") ||
            id.includes("/node_modules/d3") ||
            id.includes("/node_modules/dagre") ||
            id.includes("/node_modules/khroma/") ||
            id.includes("/node_modules/cytoscape") ||
            id.includes("/node_modules/lodash-es/") ||
            id.includes("/node_modules/elkjs/") ||
            id.includes("/node_modules/katex/") ||
            id.includes("/node_modules/stylis/")
          ) {
            return "mermaid-vendor";
          }

          if (id.includes("node_modules")) {
            return "vendor";
          }
        },
      },
    },
  },
});
