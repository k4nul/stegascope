export type JobStatus = "queued" | "running" | "done" | "failed";

export type CreateJobResponse = {
  jobId: string;
};

export type JobStatusResponse = {
  status: JobStatus;
  progress?: number;
  error?: string;
};

export type AnalysisResultResponse = {
  confidence: number;
  suspiciousRegions: number;
  note: string;
  completedAt?: string;
  suspiciousFiles?: string[];
};

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

const assertOk = async (response: Response) => {
  if (response.ok) {
    return;
  }

  const text = await response.text();
  throw new Error(text || `Request failed with status ${response.status}`);
};

export const createAnalysisJob = async (file: File): Promise<CreateJobResponse> => {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE}/analysis/jobs`, {
    method: "POST",
    body: formData,
  });
  await assertOk(response);
  return response.json() as Promise<CreateJobResponse>;
};

export const getAnalysisJobStatus = async (jobId: string): Promise<JobStatusResponse> => {
  const response = await fetch(`${API_BASE}/analysis/jobs/${jobId}`);
  await assertOk(response);
  return response.json() as Promise<JobStatusResponse>;
};

export const getAnalysisResult = async (jobId: string): Promise<AnalysisResultResponse> => {
  const response = await fetch(`${API_BASE}/analysis/jobs/${jobId}/result`);
  await assertOk(response);
  return response.json() as Promise<AnalysisResultResponse>;
};

export const downloadSuspiciousFile = async (
  jobId: string,
  fileName: string,
): Promise<void> => {
  const response = await fetch(
    `${API_BASE}/analysis/jobs/${jobId}/suspicious-files/${encodeURIComponent(fileName)}/download`,
  );
  await assertOk(response);

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};
