// Rebuild the homepage's local animation module and retain the upstream MIT notice.
const { build } = require("esbuild");
const { readFile, writeFile, mkdir } = require("node:fs/promises");
const { dirname, resolve } = require("node:path");

async function main() {
  const packageRoot = dirname(require.resolve("animejs/package.json"));
  const metadata = JSON.parse(await readFile(resolve(packageRoot, "package.json"), "utf8"));
  if (metadata.version !== "4.5.0" || metadata.license !== "MIT") {
    throw new Error("Expected MIT-licensed animejs 4.5.0. Review the dependency before updating.");
  }
  const destination = resolve(__dirname, "../content/assets/javascripts/vendor/anime.js");
  const licenseDestination = resolve(__dirname, "../content/assets/licenses/animejs-MIT.txt");
  const license = await readFile(resolve(packageRoot, "LICENSE.md"), "utf8");
  await mkdir(dirname(destination), { recursive: true });
  await mkdir(dirname(licenseDestination), { recursive: true });
  await build({
    stdin: {
      contents: 'export { createTimeline, createDrawable, createMotionPath, cubicBezier, stagger } from "animejs";',
      resolveDir: __dirname,
    },
    bundle: true,
    minify: true,
    format: "esm",
    target: ["es2020"],
    legalComments: "none",
    banner: { js: `/* Anime.js ${metadata.version}\n${license.trim()}\n*/` },
    outfile: destination,
  });
  await writeFile(licenseDestination, license);
  console.log(`Anime.js ${metadata.version} (MIT): ${destination}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
