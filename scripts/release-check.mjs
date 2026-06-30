import { readFileSync } from "node:fs";

const sourceVersion = readFileSync(new URL("../VERSION", import.meta.url), "utf8").trim();
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const packageVersion = pkg.version;
const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
const cliSource = readFileSync(new URL("../cli/internal/cli/cli.go", import.meta.url), "utf8");
const cliVersion = cliSource.match(/var\s+Version\s*=\s*"([^"]+)"/)?.[1];
const installerSource = readFileSync(new URL("../scripts/install.sh", import.meta.url), "utf8");
const installerVersion = installerSource.match(/^VERSION="\$\{ASIRI_VERSION:-([^}]+)\}"/m)?.[1];
const buildVersion = process.env.ASIRI_VERSION || sourceVersion;
const githubTag = process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : "";
const tag = process.env.ASIRI_RELEASE_TAG || githubTag || "";
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const failures = [];

if (!semver.test(sourceVersion)) failures.push(`VERSION must be semver: ${sourceVersion}`);
if (!semver.test(packageVersion)) failures.push(`package version must be semver: ${packageVersion}`);
if (!semver.test(buildVersion)) failures.push(`build version must be semver: ${buildVersion}`);
if (buildVersion !== sourceVersion) failures.push(`build version ${buildVersion} must match VERSION ${sourceVersion}`);
if (packageVersion !== sourceVersion) failures.push(`package version ${packageVersion} must match VERSION ${sourceVersion}`);
if (lock.version !== packageVersion) failures.push(`package-lock version ${lock.version} must match package version ${packageVersion}`);
if (lock.packages?.[""]?.version !== packageVersion) failures.push(`package-lock root version ${lock.packages?.[""]?.version} must match package version ${packageVersion}`);
if (cliVersion !== packageVersion) failures.push(`CLI default version ${cliVersion} must match package version ${packageVersion}`);
if (installerVersion !== packageVersion) failures.push(`installer default version ${installerVersion || "<missing>"} must match package version ${packageVersion}`);

if (tag) {
  if (!tag.startsWith("v")) {
    failures.push(`release tag must start with v: ${tag}`);
  } else if (tag.slice(1) !== packageVersion) {
    failures.push(`release tag ${tag} must match package version ${packageVersion}`);
  }
}

if (failures.length > 0) {
  console.error("Release check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Release check passed for v${packageVersion}`);
