import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const version = readText("VERSION").trim();

if (!semver.test(version)) {
  console.error(`VERSION must contain a semver value, got: ${version || "<empty>"}`);
  process.exit(1);
}

const packageJson = readJson("package.json");
packageJson.version = version;
writeJson("package.json", packageJson);

const lock = readJson("package-lock.json");
lock.version = version;
if (lock.packages?.[""]) {
  lock.packages[""].version = version;
}
writeJson("package-lock.json", lock);

replaceInFile("cli/internal/cli/cli.go", /var\s+Version\s*=\s*"[^"]+"/, `var Version = "${version}"`);
replaceInFile("scripts/install.sh", /^VERSION="\$\{ASIRI_VERSION:-[^}]+\}"/m, `VERSION="\${ASIRI_VERSION:-${version}}"`);

console.log(`Synced Asiri version ${version}`);

function readText(path) {
  return readFileSync(new URL(path, root), "utf8");
}

function writeText(path, value) {
  writeFileSync(new URL(path, root), value);
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function writeJson(path, value) {
  writeText(path, `${JSON.stringify(value, null, 2)}\n`);
}

function replaceInFile(path, pattern, replacement) {
  const input = readText(path);
  const output = input.replace(pattern, replacement);
  if (output === input) {
    console.error(`Could not update ${path}; expected pattern was not found.`);
    process.exit(1);
  }
  writeText(path, output);
}
