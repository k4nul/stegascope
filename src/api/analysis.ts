import { invoke } from "@tauri-apps/api/core";

export type SuspiciousLevel = "unknown" | "low" | "medium" | "high" | "critical";
export type ValidationStatus = "verified" | "validated" | "candidate" | "rejected";

export type FileSignature = {
  isKnown: boolean;
  label: string;
  extension: string | null;
  mimeType: string | null;
  headerHex: string;
};

export type CreateTaskInput = {
  caseNumber: string;
  caseName: string;
  investigatorName: string;
  date: string;
};

export type MediaFileInfo = {
  fileName: string;
  fileSizeBytes: number;
  fileType: string;
};

export type ExtractedFile = {
  fileName: string;
  analyzerName: string;
  suspiciousLevel: SuspiciousLevel;
  validationStatus: ValidationStatus;
  validationNote: string;
  fileSizeBytes: number;
  fileType: string;
  fileSignature: FileSignature;
};

export type TaskResponse = {
  taskId: string;
  caseNumber: string;
  caseName: string;
  investigatorName: string;
  date: string;
  mediaFile: MediaFileInfo | null;
  extractedFiles: ExtractedFile[];
};

export type AnalysisResultResponse = {
  taskId: string;
  confidence: number;
  suspiciousRegions: number;
  note: string;
  completedAt: string;
  extractedFiles: ExtractedFile[];
};

export type DownloadExtractedFileResponse = {
  fileName: string;
  fileType: string;
  savedPath: string;
};

type UploadedMediaInput = {
  fileName: string;
  fileSizeBytes: number;
  fileType: string;
  bytes: number[];
};

export const createTask = async (input: CreateTaskInput): Promise<TaskResponse> => {
  return invoke<TaskResponse>("create_task", { input });
};

export const attachMediaFile = async (
  taskId: string,
  file: File,
): Promise<TaskResponse> => {
  const input: UploadedMediaInput = {
    fileName: file.name,
    fileSizeBytes: file.size,
    fileType: file.type || inferMediaType(file.name),
    bytes: Array.from(new Uint8Array(await file.arrayBuffer())),
  };

  return invoke<TaskResponse>("attach_media_file", { taskId, input });
};

export const analyzeTask = async (taskId: string): Promise<AnalysisResultResponse> => {
  return invoke<AnalysisResultResponse>("analyze_task", { taskId });
};

export const getExtractedFiles = async (taskId: string): Promise<ExtractedFile[]> => {
  return invoke<ExtractedFile[]>("get_extracted_files", { taskId });
};

export const downloadExtractedFile = async (
  taskId: string,
  fileName: string,
  analyzerName: string,
  targetPath: string,
): Promise<DownloadExtractedFileResponse> => {
  return invoke<DownloadExtractedFileResponse>("download_extracted_file", {
    taskId,
    fileName,
    analyzerName,
    targetPath,
  });
};

const inferMediaType = (fileName: string) => {
  const extension = fileName.split(".").pop()?.toLowerCase();

  switch (extension) {
    case "apng":
    case "avif":
    case "bmp":
    case "gif":
    case "jpg":
    case "jpeg":
    case "png":
    case "webp":
      return `image/${extension}`;
    case "flac":
    case "m4a":
    case "mp3":
    case "ogg":
    case "wav":
    case "weba":
      return `audio/${extension}`;
    case "avi":
    case "m4v":
    case "mkv":
    case "mov":
    case "mp4":
    case "mpeg":
    case "webm":
      return `video/${extension}`;
    default:
      return "application/octet-stream";
  }
};
