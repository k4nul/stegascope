import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));

const readProjectFile = (path) =>
  readFileSync(resolve(rootDir, path), "utf8");

const checks = [];
const allowedDependencyFreeImports = new Set([
  "./validate-download-ipc.mjs",
  "node:fs",
  "node:path",
  "node:url",
]);

const expectCondition = (label, condition) => {
  checks.push(label);
  if (!condition) {
    throw new Error(`download IPC contract check failed: ${label}`);
  }
};

const expectMatch = (label, source, pattern) => {
  checks.push(label);
  if (!pattern.test(source)) {
    throw new Error(`download IPC contract check failed: ${label}`);
  }
};

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const rustTestFunctionPattern = (testName) =>
  new RegExp(`#\\s*\\[\\s*test\\s*\\]\\s*fn\\s+${escapeRegExp(testName)}\\s*\\(`);

const expectRustTestFunction = (label, source, testName) => {
  expectMatch(label, source, rustTestFunctionPattern(testName));
};

const projectFiles = (directory) => {
  const absoluteDirectory = resolve(rootDir, directory);
  const files = [];

  for (const entry of readdirSync(absoluteDirectory)) {
    const absolutePath = resolve(absoluteDirectory, entry);
    const relativePath = `${directory}/${entry}`;
    const stats = statSync(absolutePath);

    if (stats.isDirectory()) {
      files.push(...projectFiles(relativePath));
    } else {
      files.push(relativePath);
    }
  }

  return files;
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

const frontendSourceFiles = () =>
  projectFiles("src").filter((path) => /\.(ts|tsx)$/.test(path));

const validateDownloadCallsitesUsePayloadIds = () => {
  const callsites = [];

  for (const path of frontendSourceFiles()) {
    const source = readProjectFile(path);
    const callPattern = /downloadExtractedFile\s*\(([\s\S]*?)\)/g;

    for (const match of source.matchAll(callPattern)) {
      if (path === "src/api/analysis.ts" && /async\s*$/.test(source.slice(0, match.index))) {
        continue;
      }

      callsites.push({ path, args: match[1] });
      expectCondition(
        `${path} downloadExtractedFile call uses file.id`,
        /\bfile\.id\b/.test(match[1]),
      );
      expectCondition(
        `${path} downloadExtractedFile call does not pass legacy metadata identity`,
        !/\bfile\.(fileName|analyzerName)\b/.test(match[1]),
      );
    }
  }

  expectCondition(
    "frontend has at least one downloadExtractedFile callsite",
    callsites.length > 0,
  );
};

export const validateDownloadIpcContract = () => {
checks.length = 0;

validateDependencyFreeImports("scripts/validate-download-ipc.mjs");

const apiSource = readProjectFile("src/api/analysis.ts");
const appSource = readProjectFile("src/App.tsx");
const rustSource = readProjectFile("src-tauri/src/lib.rs");
const analyzerSource = readProjectFile("src-tauri/src/domain/analyzer.rs");
const analyzerPipelineSource = readProjectFile(
  "src-tauri/src/domain/analyzer_pipeline.rs",
);
const taskSource = readProjectFile("src-tauri/src/domain/task.rs");
const extractedFileSource = readProjectFile(
  "src-tauri/src/domain/extracted_file.rs",
);
const testingDocs = readProjectFile("docs/testing.md");
const phaseGates = JSON.parse(readProjectFile("docs/instructions/phase-gates.json"));
const payloadGate = phaseGates.required_gates?.find(
  (gate) => gate.id === "payload-id-download-disambiguation",
);
const requiredPayloadEvidence = [
  "finalize_extracted_payloads",
  "assign_payload_ids",
  "assign_payload_ids_uses_recovered_bytes_for_same_name_payloads",
  "assign_payload_ids_is_stable_for_identical_payload_identity",
  "assign_payload_ids_separates_payload_source_and_analyzer_identity",
  "assign_payload_ids_separates_embedded_name_and_file_type",
  "replace_extracted_payloads_dedupes_exact_payloads_before_assigning_ids",
  "replace_extracted_payloads_prefers_verified_payloads_before_assigning_ids",
  "metadata_analyzer_preserves_distinct_packets_with_same_embedded_name",
  "download_extracted_file_command_test_writes_current_payload_bytes",
  "download_extracted_file_command_test_rejects_stale_payload_id_after_result_replacement",
  "download_extracted_file_command_test_uses_file_id_for_same_name_payloads",
  "download_extracted_file_command_test_uses_file_id_for_same_name_signature_scan_payloads",
  "download_extracted_file_command_test_rejects_blank_payload_id",
  "download_extracted_file_command_test_rejects_missing_payload_bytes",
  "analyze_and_download_command_test_disambiguates_same_name_packet_payloads",
  "analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_payloads",
  "analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_after_eoi_payloads",
  "analyze_and_download_command_test_rejects_payload_id_after_reattach",
];

const downloadWrapper = apiSource.match(
  /export const downloadExtractedFile = async \([\s\S]*?\n\};/,
)?.[0];

if (!downloadWrapper) {
  throw new Error(
    "download IPC contract check failed: API wrapper was not found",
  );
}

expectMatch(
  "frontend extracted file metadata exposes id",
  apiSource,
  /export type ExtractedFile = \{[\s\S]*?\n\s+id: string;/,
);
expectMatch(
  "Rust extracted file metadata serializes id",
  extractedFileSource,
  /pub struct ExtractedFile \{[\s\S]*?\n\s+pub id: String,/,
);
expectMatch(
  "frontend API wrapper accepts fileId",
  downloadWrapper,
  /taskId: string,\s+fileId: string,\s+targetPath: string,/,
);
expectMatch(
  "frontend API wrapper sends fileId to Tauri",
  downloadWrapper,
  /invoke<DownloadExtractedFileResponse>\("download_extracted_file", \{\s+taskId,\s+fileId,\s+targetPath,\s+\}\);/,
);

if (/\bfileName: string\b|\banalyzerName: string\b/.test(downloadWrapper)) {
  throw new Error(
    "download IPC contract check failed: API wrapper still accepts legacy fileName/analyzerName arguments",
  );
}

expectMatch(
  "app download handler passes file.id",
  appSource,
  /downloadExtractedFile\(\s+activeTab\.taskId,\s+file\.id,\s+targetPath,\s+\)/,
);
validateDownloadCallsitesUsePayloadIds();
expectMatch(
  "app extracted file list is keyed by file.id",
  appSource,
  /<li key=\{file\.id\}>/,
);
expectMatch(
  "Rust command accepts file_id",
  rustSource,
  /fn download_extracted_file\(\s+task_id: String,\s+file_id: String,\s+target_path: String,/,
);
expectMatch(
  "Rust command remains registered in Tauri handler",
  rustSource,
  /invoke_handler\(tauri::generate_handler!\[[\s\S]*?download_extracted_file[\s\S]*?\]\)/,
);
expectMatch(
  "Rust command rejects blank file_id before lookup",
  rustSource,
  /validate_required\(&file_id, "file id"\)\?;\s+validate_required\(&target_path, "save path"\)\?;\s+let file_id = file_id\.trim\(\);/,
);
expectMatch(
  "Rust download lookup resolves current payload by id",
  rustSource,
  /\.find\(\|payload\| payload\.file\.id == file_id\)/,
);
expectMatch(
  "Rust finalization assigns IDs after dedupe",
  analyzerPipelineSource,
  /pub fn finalize_extracted_payloads[\s\S]*?dedupe_payloads\(&mut payloads\);[\s\S]*?assign_payload_ids\(&mut payloads\);[\s\S]*?payloads/,
);
expectMatch(
  "Rust analyzer-local outcome path assigns IDs after dedupe",
  analyzerSource,
  /pub fn from_payloads\(mut extracted_payloads: Vec<ExtractedPayload>\) -> Self \{[\s\S]*?dedupe_payloads\(&mut extracted_payloads\);[\s\S]*?assign_payload_ids\(&mut extracted_payloads\);/,
);
expectMatch(
  "Rust assign_payload_ids replaces legacy metadata IDs",
  analyzerPipelineSource,
  /pub\(crate\) fn assign_payload_ids\(payloads: &mut \[ExtractedPayload\]\) \{[\s\S]*?payload\.file\.id = payload_identifier\(payload\);[\s\S]*?\}/,
);
expectMatch(
  "Rust payload ID hash includes analyzer identity",
  analyzerPipelineSource,
  /fn payload_identifier[\s\S]*?hasher\.update\(payload\.file\.analyzer_name\.as_bytes\(\)\);/,
);
expectMatch(
  "Rust payload ID hash includes embedded file name",
  analyzerPipelineSource,
  /fn payload_identifier[\s\S]*?hasher\.update\(payload\.file\.file_name\.as_bytes\(\)\);/,
);
expectMatch(
  "Rust payload ID hash includes file type",
  analyzerPipelineSource,
  /fn payload_identifier[\s\S]*?hasher\.update\(payload\.file\.file_type\.as_bytes\(\)\);/,
);
expectMatch(
  "Rust payload ID hash separates payload source",
  analyzerPipelineSource,
  /match payload\.source \{[\s\S]*?PayloadSource::VerifiedPacket[\s\S]*?verified-packet[\s\S]*?PayloadSource::SignatureScan[\s\S]*?signature-scan/,
);
expectMatch(
  "Rust payload ID hash includes recovered bytes",
  analyzerPipelineSource,
  /fn payload_identifier[\s\S]*?hasher\.update\(&payload\.bytes\);/,
);
expectMatch(
  "Rust payload ID uses payload prefix",
  analyzerPipelineSource,
  /format!\("payload-\{\}", digest_to_hex\(&digest\)\)/,
);
expectMatch(
  "Rust exact-payload dedupe includes source and bytes",
  analyzerPipelineSource,
  /fn same_payload_identity[\s\S]*?left\.source == right\.source[\s\S]*?left\.bytes == right\.bytes/,
);
expectMatch(
  "Task replacement finalizes payloads before storage",
  taskSource,
  /pub fn replace_extracted_payloads[\s\S]*?let payloads = finalize_extracted_payloads\(payloads\);[\s\S]*?self\.extracted_files = payloads[\s\S]*?self\.extracted_payloads = payloads;/,
);
expectCondition(
  "phase gate declares payload-id download disambiguation",
  Boolean(payloadGate),
);
expectCondition(
  "phase gate requires payload-id download disambiguation for transition",
  payloadGate?.required_for_transition === true,
);
expectCondition(
  "phase gate lists dependency-free IPC validator",
  payloadGate?.evidence?.includes("npm run validate:download-ipc"),
);
for (const evidence of requiredPayloadEvidence) {
  expectCondition(
    `phase gate lists ${evidence}`,
    payloadGate?.evidence?.includes(evidence),
  );
}
const payloadEvidenceSources = new Map([
  ["finalize_extracted_payloads", analyzerPipelineSource],
  ["assign_payload_ids", analyzerPipelineSource],
  [
    "assign_payload_ids_uses_recovered_bytes_for_same_name_payloads",
    analyzerPipelineSource,
  ],
  [
    "assign_payload_ids_is_stable_for_identical_payload_identity",
    analyzerPipelineSource,
  ],
  [
    "assign_payload_ids_separates_payload_source_and_analyzer_identity",
    analyzerPipelineSource,
  ],
  ["assign_payload_ids_separates_embedded_name_and_file_type", analyzerPipelineSource],
  [
    "replace_extracted_payloads_dedupes_exact_payloads_before_assigning_ids",
    taskSource,
  ],
  [
    "replace_extracted_payloads_prefers_verified_payloads_before_assigning_ids",
    taskSource,
  ],
  [
    "metadata_analyzer_preserves_distinct_packets_with_same_embedded_name",
    analyzerSource,
  ],
  ["download_extracted_file_command_test_writes_current_payload_bytes", rustSource],
  [
    "download_extracted_file_command_test_rejects_stale_payload_id_after_result_replacement",
    rustSource,
  ],
  [
    "download_extracted_file_command_test_uses_file_id_for_same_name_payloads",
    rustSource,
  ],
  [
    "download_extracted_file_command_test_uses_file_id_for_same_name_signature_scan_payloads",
    rustSource,
  ],
  ["download_extracted_file_command_test_rejects_blank_payload_id", rustSource],
  ["download_extracted_file_command_test_rejects_missing_payload_bytes", rustSource],
  [
    "analyze_and_download_command_test_disambiguates_same_name_packet_payloads",
    rustSource,
  ],
  [
    "analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_payloads",
    rustSource,
  ],
  [
    "analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_after_eoi_payloads",
    rustSource,
  ],
  ["analyze_and_download_command_test_rejects_payload_id_after_reattach", rustSource],
]);
const payloadTestEvidence = new Set(
  requiredPayloadEvidence.filter(
    (evidence) =>
      !["assign_payload_ids", "finalize_extracted_payloads"].includes(evidence),
  ),
);
for (const [evidence, source] of payloadEvidenceSources) {
  expectMatch(
    `source defines ${evidence}`,
    source,
    new RegExp(`\\b${evidence}\\b`),
  );
  if (payloadTestEvidence.has(evidence)) {
    expectRustTestFunction(
      `source defines #[test] fn ${evidence}`,
      source,
      evidence,
    );
  }
}
expectMatch(
  "testing docs list dependency-free IPC validator",
  testingDocs,
  /npm run validate:download-ipc/,
);

return checks.length;
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const checkCount = validateDownloadIpcContract();
  console.log(`download IPC contract validated (${checkCount} checks)`);
}
