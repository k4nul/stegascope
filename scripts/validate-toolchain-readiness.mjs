import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const checks = [];
const jsonOutput = process.argv.includes("--json");

const readProjectFile = (path) =>
  readFileSync(resolve(rootDir, path), "utf8");

const addCheck = ({ id, label, status, detail, action }) => {
  checks.push({ id, label, status, detail, action });
};

const addFileCheck = (id, label, path, action) => {
  const exists = existsSync(resolve(rootDir, path));
  addCheck({
    id,
    label,
    status: exists ? "pass" : "blocker",
    detail: exists ? `${path} exists` : `${path} is missing`,
    action,
  });
};

const hasLocalBin = (name) =>
  ["", ".cmd", ".ps1"].some((suffix) =>
    existsSync(resolve(rootDir, "node_modules", ".bin", `${name}${suffix}`)),
  );

const addLocalBinCheck = (name, action) => {
  const exists = hasLocalBin(name);
  addCheck({
    id: `local-${name}-binary`,
    label: `local ${name} binary`,
    status: exists ? "pass" : "blocker",
    detail: exists
      ? `node_modules/.bin/${name} is available`
      : `node_modules/.bin/${name} is missing`,
    action,
  });
};

const addManifestScriptCheck = (manifest, scriptName, expected) => {
  const actual = manifest.scripts?.[scriptName];
  addCheck({
    id: `npm-script-${scriptName}`,
    label: `npm script ${scriptName}`,
    status: actual === expected ? "pass" : "blocker",
    detail:
      actual === expected
        ? `${scriptName} is ${expected}`
        : `${scriptName} is ${actual ?? "missing"}`,
    action: `Restore package.json scripts.${scriptName} to ${expected}.`,
  });
};

const addCargoDependencyResolutionCheck = () => {
  const result = spawnSync(
    process.env.CARGO ?? "cargo",
    [
      "metadata",
      "--manifest-path",
      "src-tauri/Cargo.toml",
      "--locked",
      "--offline",
      "--format-version=1",
    ],
    {
      cwd: rootDir,
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    },
  );

  const output = `${result.stderr ?? ""}${result.stdout ?? ""}`
    .trim()
    .split("\n")
    .find(Boolean);

  if (result.status === 0) {
    addCheck({
      id: "cargo-dependency-resolution-offline",
      label: "offline Cargo dependency resolution",
      status: "pass",
      detail: "cargo metadata resolved the locked dependency graph offline",
      action:
        "Restore Cargo cache/network access before treating Rust checks as source failures.",
    });
    return;
  }

  if (result.error) {
    const action =
      result.error.code === "ENOENT"
        ? "Install Cargo/Rust tooling before running Rust validation."
        : result.error.code === "EPERM"
          ? "Allow Cargo dependency resolution in this environment before running Rust validation."
        : "Make the Cargo executable accessible in this environment before running Rust validation.";
    addCheck({
      id: "cargo-dependency-resolution-offline",
      label: "offline Cargo dependency resolution",
      status: "blocker",
      detail: result.error.message,
      action,
    });
    return;
  }

  addCheck({
    id: "cargo-dependency-resolution-offline",
    label: "offline Cargo dependency resolution",
    status: "blocker",
    detail: output ?? `cargo metadata exited with ${result.status}`,
    action:
      "Restore the locked Cargo registry data or network access before running Rust validation.",
  });
};

const packageManifest = JSON.parse(readProjectFile("package.json"));
const packageLock = JSON.parse(readProjectFile("package-lock.json"));

addManifestScriptCheck(packageManifest, "build", "tsc && vite build");
addManifestScriptCheck(
  packageManifest,
  "validate:toolchain-readiness",
  "node scripts/validate-toolchain-readiness.mjs",
);
addFileCheck(
  "package-lock",
  "npm lockfile",
  "package-lock.json",
  "Restore the checked-in npm lockfile before running npm setup.",
);
addFileCheck(
  "cargo-lock",
  "Cargo lockfile",
  "src-tauri/Cargo.lock",
  "Restore the checked-in Cargo lockfile before running Rust validation.",
);

for (const dependency of ["typescript", "vite"]) {
  addCheck({
    id: `package-dev-dependency-${dependency}`,
    label: `package dev dependency ${dependency}`,
    status: packageManifest.devDependencies?.[dependency] ? "pass" : "blocker",
    detail: packageManifest.devDependencies?.[dependency]
      ? `${dependency} is declared`
      : `${dependency} is missing`,
    action: `Restore the checked-in ${dependency} dev dependency before build validation.`,
  });
}

for (const dependencyPath of ["node_modules/typescript", "node_modules/vite"]) {
  addCheck({
    id: `lockfile-${dependencyPath.replaceAll("/", "-")}`,
    label: `lockfile entry ${dependencyPath}`,
    status: packageLock.packages?.[dependencyPath] ? "pass" : "blocker",
    detail: packageLock.packages?.[dependencyPath]
      ? `${dependencyPath} is locked`
      : `${dependencyPath} is missing from package-lock.json`,
    action: "Restore package-lock.json from the checked-in dependency set.",
  });
}

addLocalBinCheck("tsc", "Run npm ci, then rerun npm run build.");
addLocalBinCheck("vite", "Run npm ci, then rerun npm run build.");
addCargoDependencyResolutionCheck();

const blockers = checks.filter((check) => check.status === "blocker");
const result = {
  status: blockers.length === 0 ? "ready" : "blocked",
  checks,
};

if (jsonOutput) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`toolchain readiness: ${result.status}`);
  for (const check of checks) {
    console.log(`- ${check.status}: ${check.label}: ${check.detail}`);
    if (check.status === "blocker") {
      console.log(`  action: ${check.action}`);
    }
  }
}

process.exit(blockers.length === 0 ? 0 : 1);
