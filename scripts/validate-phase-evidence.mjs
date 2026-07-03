import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateDownloadIpcContract } from "./validate-download-ipc.mjs";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));

const readProjectFile = (path) =>
  readFileSync(resolve(rootDir, path), "utf8");

const checks = [];
const allowedDependencyFreeImports = new Set([
  "./validate-download-ipc.mjs",
  "node:child_process",
  "node:fs",
  "node:path",
  "node:url",
]);

const expectCondition = (label, condition) => {
  checks.push(label);
  if (!condition) {
    throw new Error(`phase evidence check failed: ${label}`);
  }
};

const expectMatch = (label, source, pattern) => {
  checks.push(label);
  if (!pattern.test(source)) {
    throw new Error(`phase evidence check failed: ${label}`);
  }
};

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const rustTestFunctionPattern = (testName) =>
  new RegExp(`#\\s*\\[\\s*test\\s*\\]\\s*fn\\s+${escapeRegExp(testName)}\\s*\\(`);

const expectRustTestFunction = (label, source, testName) => {
  expectMatch(label, source, rustTestFunctionPattern(testName));
};

const rustTestFunctionNames = (source) =>
  [...source.matchAll(/#\s*\[\s*test\s*\]\s*fn\s+([A-Za-z0-9_]+)\s*\(/g)].map(
    (match) => match[1],
  );

const cargoTestFilter = (command) => {
  const prefix = "cargo test --manifest-path src-tauri/Cargo.toml";

  if (!command.startsWith(prefix)) {
    return null;
  }

  const filter = command.slice(prefix.length).trim();
  return filter.length > 0 ? filter : "";
};

const validateDependencyFreeImports = (scriptPath) => {
  const source = readProjectFile(scriptPath);
  const importPattern = /import\s+(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']/g;

  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1];
    expectCondition(
      `${scriptPath} keeps dependency-free import ${specifier}`,
      allowedDependencyFreeImports.has(specifier),
    );
  }
};

const packageManifest = JSON.parse(readProjectFile("package.json"));
const phaseGates = JSON.parse(readProjectFile("docs/instructions/phase-gates.json"));
const analyzerSource = readProjectFile("src-tauri/src/domain/analyzer.rs");
const analyzerPipelineSource = readProjectFile(
  "src-tauri/src/domain/analyzer_pipeline.rs",
);
const rustCommandSource = readProjectFile("src-tauri/src/lib.rs");
const taskSource = readProjectFile("src-tauri/src/domain/task.rs");
const appSource = readProjectFile("src/App.tsx");
const apiSource = readProjectFile("src/api/analysis.ts");
const readmeDocs = readProjectFile("README.md");
const architectureDocs = readProjectFile("docs/architecture.md");
const onboardingDocs = readProjectFile("docs/onboarding.md");
const maintenanceDocs = readProjectFile("docs/maintenance.md");
const phaseReadinessDocs = readProjectFile("docs/phase-readiness.md");
const testingDocs = readProjectFile("docs/testing.md");
const troubleshootingDocs = readProjectFile("docs/troubleshooting.md");

const requiredGateIds = [
  "frontend-build-passes",
  "rust-analyzer-tests-exist",
  "local-file-boundary-evidence",
  "payload-id-download-disambiguation",
  "jpeg-segment-analyzer-exists",
  "png-deep-container-scan-exists",
];

const gateById = new Map(
  phaseGates.required_gates?.map((gate) => [gate.id, gate]) ?? [],
);
const phaseById = new Map(
  phaseGates.phase_model?.map((phase) => [phase.id, phase]) ?? [],
);

validateDependencyFreeImports("scripts/validate-phase-evidence.mjs");
validateDependencyFreeImports("scripts/validate-toolchain-readiness.mjs");

expectCondition(
  "package build script keeps TypeScript and Vite gate",
  packageManifest.scripts?.build === "tsc && vite build",
);
expectCondition(
  "package declares local TypeScript compiler dependency for build gate",
  Boolean(packageManifest.devDependencies?.typescript),
);
expectCondition(
  "package declares local Vite dependency for build gate",
  Boolean(packageManifest.devDependencies?.vite),
);
expectCondition(
  "package exposes download IPC validator",
  packageManifest.scripts?.["validate:download-ipc"] ===
    "node scripts/validate-download-ipc.mjs",
);
expectCondition(
  "package exposes phase evidence validator",
  packageManifest.scripts?.["validate:phase-evidence"] ===
    "node scripts/validate-phase-evidence.mjs",
);
expectCondition(
  "package exposes toolchain readiness validator",
  packageManifest.scripts?.["validate:toolchain-readiness"] ===
    "node scripts/validate-toolchain-readiness.mjs",
);
expectCondition(
  "package exposes dependency-free static validator chain",
  packageManifest.scripts?.["validate:static"] ===
    "node --check scripts/validate-download-ipc.mjs && node --check scripts/validate-phase-evidence.mjs && node --check scripts/validate-toolchain-readiness.mjs && node scripts/validate-phase-evidence.mjs",
);
expectCondition(
  "phase manifest stays on container-side-channels",
  phaseGates.current_phase === "container-side-channels",
);
expectCondition(
  "phase manifest points next to audio-lsb-analysis",
  phaseGates.next_phase === "audio-lsb-analysis",
);
expectCondition(
  "phase transition command remains npm run build",
  phaseGates.transition?.transition_validation_command === "npm run build",
);
expectCondition(
  "phase validation command remains npm run build",
  phaseGates.transition?.validation_command === "npm run build",
);

const expectPhaseModelIncludes = (phaseId, property, evidence) => {
  const phase = phaseById.get(phaseId);
  expectCondition(`phase model declares ${phaseId}`, Boolean(phase));
  expectCondition(
    `${phaseId} ${property} lists ${evidence}`,
    phase?.[property]?.includes(evidence),
  );
};

for (const allowedWork of [
  "JPEG segment analysis",
  "PNG deep container analysis",
  "Rust analyzer tests",
  "local file boundary evidence",
  "deterministic payload ID download disambiguation",
  "frontend build validation",
]) {
  expectPhaseModelIncludes("container-side-channels", "allowed_work", allowedWork);
}

for (const exitCriterion of [
  "JPEG segment analyzer exists",
  "PNG deep container scan exists",
  "Rust analyzer tests cover the package",
  "local file boundary evidence exists",
  "same-name payload ID download lookup exists",
  "frontend build passes",
]) {
  expectPhaseModelIncludes(
    "container-side-channels",
    "exit_criteria",
    exitCriterion,
  );
}

expectPhaseModelIncludes("audio-lsb-analysis", "allowed_work", "WAV PCM sample LSB analysis");
expectPhaseModelIncludes("audio-lsb-analysis", "allowed_work", "focused analyzer tests");
expectCondition(
  "audio-lsb-analysis purpose treats WAV analyzer as existing pre-transition evidence",
  /Validate and formalize the existing WAV PCM LSB analyzer package/.test(
    phaseById.get("audio-lsb-analysis")?.purpose ?? "",
  ),
);
expectPhaseModelIncludes(
  "audio-lsb-analysis",
  "exit_criteria",
  "WAV PCM LSB analyzer evidence is validated",
);
expectPhaseModelIncludes(
  "audio-lsb-analysis",
  "exit_criteria",
  "audio analyzer tests pass",
);

for (const gateId of requiredGateIds) {
  const gate = gateById.get(gateId);
  expectCondition(`phase manifest declares ${gateId}`, Boolean(gate));
  expectCondition(
    `${gateId} is required for transition`,
    gate?.required_for_transition === true,
  );
}

const expectGateEvidence = (gateId, evidence) => {
  const gate = gateById.get(gateId);
  expectCondition(
    `${gateId} lists ${evidence}`,
    gate?.evidence?.includes(evidence),
  );
};

const wavPretransitionGate = gateById.get("wav-pcm-lsb-pretransition-evidence");
expectCondition(
  "phase manifest declares wav-pcm-lsb-pretransition-evidence",
  Boolean(wavPretransitionGate),
);
expectCondition(
  "wav-pcm-lsb-pretransition-evidence stays informational",
  wavPretransitionGate?.required_for_transition === false,
);

expectGateEvidence("frontend-build-passes", "npm run build");

const rustTestSources = [
  analyzerSource,
  analyzerPipelineSource,
  rustCommandSource,
  taskSource,
].join("\n");
const rustTestNames = rustTestFunctionNames(rustTestSources);

for (const gate of phaseGates.required_gates ?? []) {
  for (const evidence of gate.evidence ?? []) {
    const filter = cargoTestFilter(evidence);
    if (filter === null) {
      continue;
    }

    expectCondition(
      `${gate.id} command is documented in testing docs: ${evidence}`,
      testingDocs.includes(evidence),
    );

    if (filter === "") {
      continue;
    }

    expectCondition(
      `${gate.id} cargo test filter matches at least one Rust test: ${filter}`,
      rustTestNames.some((testName) => testName.includes(filter)),
    );
  }
}

for (const evidence of [
  "metadata_analyzer_extracts_valid_signature_from_compressed_png_text_chunks",
  "metadata_analyzer_extracts_packet_payload_from_compressed_png_itxt_chunk",
  "metadata_analyzer_preserves_distinct_packets_with_same_embedded_name",
  "default_pipeline_extracts_packet_payload_from_compressed_png_ztxt_chunk",
  "default_pipeline_extracts_container_side_channel_packets_from_registered_analyzers",
  "png_container_analyzer_extracts_packet_payload_after_iend",
  "png_container_analyzer_uses_structural_iend_for_trailing_payload",
  "jpeg_segment_analyzer_extracts_packet_payload_from_comment_segment",
  "jpeg_segment_analyzer_extracts_valid_signature_after_eoi",
  "jpeg_segment_analyzer_labels_post_eoi_data_as_after_eoi_not_segment",
  "jpeg_segment_analyzer_extracts_valid_signature_from_app_segment",
  "jpeg_segment_analyzer_scans_app0_and_app15_boundary_segments",
  "jpeg_segment_analyzer_ignores_non_payload_marker_segments",
  "jpeg_segment_analyzer_uses_structural_eoi_for_trailing_payload",
  "jpeg_segment_analyzer_does_not_treat_comment_data_after_false_eoi_as_trailing_payload",
  "jpeg_segment_analyzer_does_not_scan_sos_image_data_as_segment_payload",
  "jpeg_segment_analyzer_ignores_marker_shaped_sos_image_data",
  "jpeg_segment_analyzer_ignores_byte_stuffed_eoi_in_sos_scan_data",
  "jpeg_segment_analyzer_ignores_restart_and_fill_markers_in_sos_scan_data",
  "jpeg_segment_analyzer_recovers_after_malformed_sos_marker_shaped_data",
  "jpeg_segment_analyzer_ignores_false_eoi_in_malformed_sos_marker_length",
  "jpeg_segment_analyzer_skips_post_sos_segment_payload_when_finding_after_eoi",
  "jpeg_segment_analyzer_preserves_distinct_same_name_packets_from_segment_and_after_eoi",
  "jpeg_segment_analyzer_handles_malformed_segment_lengths",
  "jpeg_segment_analyzer_returns_empty_for_non_jpeg_and_truncated_inputs",
]) {
  expectGateEvidence("rust-analyzer-tests-exist", evidence);
  expectRustTestFunction(
    `Rust source defines #[test] fn ${evidence}`,
    analyzerSource,
    evidence,
  );
}

for (const evidence of [
  "attachMediaFile",
  "attach_media_file_from_path",
  "attach_media_file_from_path_command_test_reads_local_media_path",
]) {
  expectGateEvidence("local-file-boundary-evidence", evidence);
}

expectMatch(
  "frontend API exposes attachMediaFile wrapper",
  apiSource,
  /export const attachMediaFile = async/,
);
expectMatch(
  "frontend API invokes attach_media_file_from_path",
  apiSource,
  /invoke<[^>]+>\("attach_media_file_from_path"/,
);
expectMatch(
  "app passes selected local media path to attach wrapper",
  appSource,
  /attachMediaFile\(\s*activeTab\.taskId,\s+selectedPath\s*\)/,
);
expectMatch(
  "Rust command reads local media path inside command boundary",
  rustCommandSource,
  /fs::read\(&path\)/,
);
expectMatch(
  "Rust command test covers local path attach boundary",
  rustCommandSource,
  /fn attach_media_file_from_path_command_test_reads_local_media_path/,
);

for (const evidence of [
  "JpegSegmentAnalyzer",
  "extract_jpeg_segment_payloads",
  "jpeg_payload_segments",
  "jpeg_after_eoi_payload",
]) {
  expectGateEvidence("jpeg-segment-analyzer-exists", evidence);
  expectMatch(`JPEG source defines ${evidence}`, analyzerSource, new RegExp(evidence));
}
expectMatch(
  "default analyzer registry includes JPEG segment analyzer",
  analyzerPipelineSource,
  /Box::<JpegSegmentAnalyzer>::default\(\)/,
);

for (const evidence of [
  "PngContainerAnalyzer",
  "extract_png_container_payloads",
  "png_metadata_payload_views",
  "decoded_ztxt_text",
  "itxt_text_payload",
  "png_after_iend_payload",
]) {
  expectGateEvidence("png-deep-container-scan-exists", evidence);
  expectMatch(`PNG source defines ${evidence}`, analyzerSource, new RegExp(evidence));
}
expectMatch(
  "default analyzer registry includes PNG container analyzer",
  analyzerPipelineSource,
  /Box::<PngContainerAnalyzer>::default\(\)/,
);

for (const evidence of wavPretransitionGate?.evidence ?? []) {
  if (evidence === "src-tauri/src/domain/analyzer.rs") {
    continue;
  }
  if (evidence === "src-tauri/src/domain/analyzer_pipeline.rs") {
    continue;
  }
  if (evidence === "Box::<WavPcmLsbAnalyzer>::default()") {
    expectMatch(
      "default analyzer registry includes manifest-listed WAV PCM LSB analyzer",
      analyzerPipelineSource,
      /Box::<WavPcmLsbAnalyzer>::default\(\)/,
    );
    continue;
  }
  if (evidence.startsWith("cargo test ")) {
    expectCondition(
      "WAV pre-transition evidence lists focused cargo filter",
      evidence === "cargo test --manifest-path src-tauri/Cargo.toml wav_pcm_lsb",
    );
    continue;
  }
  if (
    evidence.startsWith("wav_pcm_lsb_analyzer_") ||
    evidence === "default_pipeline_extracts_packet_payload_from_wav_pcm_lsb"
  ) {
    expectRustTestFunction(
      `Rust source defines manifest-listed #[test] fn ${evidence}`,
      analyzerSource,
      evidence,
    );
    continue;
  }
  expectMatch(
    `WAV source defines manifest-listed ${evidence}`,
    analyzerSource,
    new RegExp(escapeRegExp(evidence)),
  );
}
expectMatch(
  "default analyzer registry includes WAV PCM LSB analyzer",
  analyzerPipelineSource,
  /Box::<WavPcmLsbAnalyzer>::default\(\)/,
);

expectMatch(
  "testing docs list phase evidence validator",
  testingDocs,
  /npm run validate:phase-evidence/,
);
expectMatch(
  "testing docs warn static phase evidence does not satisfy transition gate",
  testingDocs,
  /does not satisfy the phase transition gate/,
);
expectMatch(
  "testing docs list dependency-free static validator chain",
  testingDocs,
  /npm run validate:static/,
);
expectMatch(
  "testing docs list toolchain readiness preflight",
  testingDocs,
  /npm run validate:toolchain-readiness/,
);
expectMatch(
  "testing docs describe informational WAV pre-transition evidence",
  testingDocs,
  /informational WAV pre-transition evidence/,
);
expectMatch(
  "testing docs list focused WAV PCM LSB filter",
  testingDocs,
  /cargo test --manifest-path src-tauri\/Cargo\.toml wav_pcm_lsb/,
);
expectMatch(
  "testing docs list default pipeline container-side-channel filter",
  testingDocs,
  /cargo test --manifest-path src-tauri\/Cargo\.toml default_pipeline_extracts_container_side_channel_packets_from_registered_analyzers/,
);
expectMatch(
  "README declares active container-side-channels phase",
  readmeDocs,
  /active analyzer-expansion phase is `container-side-channels`/,
);
expectMatch(
  "README declares audio-lsb-analysis as next phase",
  readmeDocs,
  /`audio-lsb-analysis` listed as the next phase/,
);
expectMatch(
  "README keeps npm build as phase transition boundary",
  readmeDocs,
  /fresh `npm run build` transition validation passes/,
);
expectMatch(
  "README lists toolchain readiness preflight",
  readmeDocs,
  /npm run validate:toolchain-readiness/,
);
expectMatch(
  "phase readiness declares current phase",
  phaseReadinessDocs,
  /current phase: `container-side-channels`/,
);
expectMatch(
  "phase readiness declares next phase",
  phaseReadinessDocs,
  /next phase: `audio-lsb-analysis`/,
);
expectMatch(
  "phase readiness keeps npm build as transition command",
  phaseReadinessDocs,
  /transition validation command: `npm run build`/,
);
expectMatch(
  "phase readiness warns static validator does not replace transition validation",
  phaseReadinessDocs,
  /does not\s+replace\s+`npm run build` or Rust analyzer tests/,
);
expectMatch(
  "phase readiness describes toolchain readiness preflight",
  phaseReadinessDocs,
  /`npm run validate:toolchain-readiness` classifies local dependency setup blockers/,
);
expectMatch(
  "phase readiness records latest static validation count",
  phaseReadinessDocs,
  /July 4, 2026 KST validation-chain handoff refresh[\s\S]*?`npm run validate:static` \(86 download IPC checks and\s+240 phase\s+evidence checks\)/,
);
expectMatch(
  "phase readiness records latest toolchain readiness blocker",
  phaseReadinessDocs,
  /July 4, 2026 KST validation-chain handoff refresh[\s\S]*?`npm run validate:toolchain-readiness` reported\s+local setup blockers/,
);
expectMatch(
  "phase readiness records latest build blocker",
  phaseReadinessDocs,
  /July 4, 2026 KST validation-chain handoff refresh[\s\S]*?`npm run build` reported `sh: 1: tsc: not found`/,
);
expectMatch(
  "phase readiness records latest cargo DNS blocker",
  phaseReadinessDocs,
  /July 4, 2026 KST validation-chain handoff refresh[\s\S]*?`cargo test --manifest-path src-tauri\/Cargo\.toml jpeg_segment_analyzer --no-run`\s+failed before project code because Cargo could not resolve\s+`index\.crates\.io` while fetching the `image` crate/,
);
expectMatch(
  "phase readiness records latest uncached npm blocker",
  phaseReadinessDocs,
  /`npm ci --offline --ignore-scripts --cache \/tmp\/stegascope-npm-cache --no-audit --fund=false`\s+failed because `yallist-3\.1\.1\.tgz` was not cached/,
);
expectMatch(
  "phase readiness records latest npm registry DNS blocker",
  phaseReadinessDocs,
  /`npm ci --ignore-scripts --cache \/tmp\/stegascope-npm-cache --prefer-offline --no-audit --fund=false`[\s\S]*?`EAI_AGAIN`[\s\S]*?`Exit handler never called!`/,
);
expectMatch(
  "phase readiness records latest offline Cargo blocker",
  phaseReadinessDocs,
  /`cargo test --manifest-path src-tauri\/Cargo\.toml --offline --no-run` failed\s+before project code because the `tauri` crate was not cached/,
);
expectMatch(
  "phase readiness records latest online Cargo DNS blocker",
  phaseReadinessDocs,
  /`cargo test --manifest-path src-tauri\/Cargo\.toml assign_payload_ids --no-run`\s+failed before project code because Cargo could not resolve\s+`index\.crates\.io` while fetching the `image` crate/,
);
expectMatch(
  "phase readiness blocks phase move until build passes",
  phaseReadinessDocs,
  /Do not move `current_phase` to `audio-lsb-analysis` until:/,
);
expectMatch(
  "phase readiness describes informational WAV pre-transition gate",
  phaseReadinessDocs,
  /`wav-pcm-lsb-pretransition-evidence` with\s+`required_for_transition: false`/,
);
expectMatch(
  "architecture docs describe Rust-owned local file attach boundary",
  architectureDocs,
  /frontend attach flow uses the Tauri dialog plugin[\s\S]*?sends that path to Rust through `attach_media_file_from_path`[\s\S]*?Rust reads the file bytes/,
);
expectMatch(
  "architecture docs list current analyzer registry",
  architectureDocs,
  /`default_analyzers\(\)` currently registers image, audio, and byte-oriented analyzers:[\s\S]*?`metadata-analyzer`[\s\S]*?`png-container-analyzer`[\s\S]*?`jpeg-segment-analyzer`[\s\S]*?`wav-pcm-lsb-analyzer`/,
);
expectMatch(
  "architecture docs describe payload ID download path",
  architectureDocs,
  /deterministic\s+opaque payload identifier[\s\S]*?task ID, payload\s+identifier, and target path[\s\S]*?current analysis result/,
);
expectMatch(
  "onboarding docs preserve frontend and Rust boundary guidance",
  onboardingDocs,
  /Keep user interface\s+state and presentation logic in `src\/`, and keep file loading, analyzer behavior,\s+payload bytes, and filesystem writes in `src-tauri\/`/,
);
expectMatch(
  "onboarding docs describe current analyzer phase evidence",
  onboardingDocs,
  /JPEG and PNG container-side-channel coverage is the current phase evidence[\s\S]*?phase\s+state remains unchanged until the transition validation gate passes/,
);
expectMatch(
  "onboarding docs describe current payload ID contract",
  onboardingDocs,
  /Downloads accept an ID only while the matching payload is in\s+the running task's current analysis result/,
);
expectMatch(
  "maintenance docs keep phase transition blocked on fresh build",
  maintenanceDocs,
  /Phase transition out of `container-side-channels` still requires a fresh\s+`npm run build` result/,
);
expectMatch(
  "maintenance docs list dependency-free static recovery chain",
  maintenanceDocs,
  /Dependency-free static recovery chain: `npm run validate:static`/,
);
expectMatch(
  "maintenance docs list toolchain readiness preflight",
  maintenanceDocs,
  /Toolchain readiness preflight: `npm run validate:toolchain-readiness`/,
);
expectMatch(
  "troubleshooting docs document tsc setup blocker",
  troubleshootingDocs,
  /`npm run build` starts with `tsc && vite build`[\s\S]*?stopped before TypeScript checked repository\s+source/,
);
expectMatch(
  "troubleshooting docs describe toolchain readiness preflight",
  troubleshootingDocs,
  /`npm run validate:toolchain-readiness` checks the local `tsc` and `vite`\s+binaries[\s\S]*?offline Cargo metadata/,
);
expectMatch(
  "troubleshooting docs describe payload ID download requirements",
  troubleshootingDocs,
  /`download_extracted_file` requires:[\s\S]*?a payload identifier from the current analysis result/,
);
expectMatch(
  "troubleshooting docs describe container analyzer boundaries",
  troubleshootingDocs,
  /PNG container analysis[\s\S]*?structural `IEND`[\s\S]*?JPEG segment analysis[\s\S]*?structural EOI marker/,
);

const downloadIpcCheckCount = validateDownloadIpcContract();
checks.push("download IPC validator passes as part of phase evidence");
console.log(`download IPC contract validated (${downloadIpcCheckCount} checks)`);

console.log(`phase evidence validated (${checks.length} checks)`);
