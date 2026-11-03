import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const serve = process.argv.includes("--serve");

// Argo CD exposes its own React instance on window; the extension must use it
// instead of bundling a second copy.
const argoGlobals = {
  name: "argocd-globals",
  setup(build) {
    const globals = { react: "React", "react-dom": "ReactDOM" };
    build.onResolve({ filter: /^react(-dom)?$/ }, (args) => ({ path: args.path, namespace: "argocd-global" }));
    build.onLoad({ filter: /.*/, namespace: "argocd-global" }, (args) => ({
      contents: `module.exports = window.${globals[args.path]};`,
      loader: "js",
    }));
  },
};

const common = {
  bundle: true,
  format: "iife",
  target: "es2019",
  loader: { ".css": "text" },
  define: { __VERSION__: JSON.stringify(pkg.version) },
  plugins: [argoGlobals],
  logLevel: "info",
};

if (serve) {
  mkdirSync("dev/vendor", { recursive: true });
  copyFileSync("node_modules/react/umd/react.development.js", "dev/vendor/react.js");
  copyFileSync("node_modules/react-dom/umd/react-dom.development.js", "dev/vendor/react-dom.js");

  const ctx = await esbuild.context({
    ...common,
    entryPoints: { "extension-trivy": "src/index.tsx", harness: "dev/main.tsx" },
    outdir: "dev/out",
    sourcemap: true,
  });
  await ctx.watch();
  const { port } = await ctx.serve({ servedir: "dev", port: 8000 });
  console.log(`Preview running at http://localhost:${port}`);
} else {
  await esbuild.build({
    ...common,
    entryPoints: ["src/index.tsx"],
    outfile: "dist/resources/extension-trivy/extension-trivy.js",
    minify: true,
    legalComments: "none",
    banner: { js: `/* argocd-trivy-extension v${pkg.version} | Apache-2.0 */` },
  });
}
