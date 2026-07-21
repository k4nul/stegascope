import { useMemo, useRef, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  analyzeTask,
  attachMediaFile,
  createTask,
  downloadExtractedFile,
  type AnalysisResultResponse,
  type ExtractedFile,
  type MediaFileInfo,
} from "./api/analysis";
import "./App.css";

type TaskPhase =
  | "draft"
  | "creating"
  | "ready"
  | "uploading"
  | "analyzing"
  | "done"
  | "failed";

type TaskFormField = "caseNumber" | "caseName" | "investigatorName" | "date";

type AnalysisTab = {
  id: number;
  title: string;
  taskId: string | null;
  caseNumber: string;
  caseName: string;
  investigatorName: string;
  date: string;
  mediaFile: MediaFileInfo | null;
  phase: TaskPhase;
  error: string | null;
  downloadPath: string | null;
  result: AnalysisResultResponse | null;
  extractedFiles: ExtractedFile[];
};

const todayForInput = (): string => {
  const date = new Date();
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 10);
};

const createTab = (id: number): AnalysisTab => ({
  id,
  title: `Task ${id}`,
  taskId: null,
  caseNumber: "",
  caseName: "",
  investigatorName: "",
  date: todayForInput(),
  mediaFile: null,
  phase: "draft",
  error: null,
  downloadPath: null,
  result: null,
  extractedFiles: [],
});

const truncateTitle = (title: string): string =>
  title.length > 22 ? `${title.slice(0, 22)}...` : title;

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unitIndex]}`;
};

const formatCompletedAt = (value: string): string => {
  if (!value.startsWith("unix:")) {
    return value;
  }

  const seconds = Number(value.slice("unix:".length));
  if (!Number.isFinite(seconds)) {
    return value;
  }

  return new Date(seconds * 1000).toLocaleString();
};

const defaultSaveName = (fileName: string): string => {
  const sanitized = fileName.replace(/[\\/:*?"<>|]/g, "_").trim();
  return sanitized || "extracted_payload";
};

const extensionFromFile = (file: ExtractedFile): string | null => {
  if (file.fileSignature.extension) {
    return file.fileSignature.extension;
  }

  const nameExtension = file.fileName.split(".").pop()?.trim().toLowerCase();
  if (nameExtension && nameExtension !== file.fileName.toLowerCase()) {
    return nameExtension.replace(/[^a-z0-9]/g, "");
  }

  return null;
};

const saveFiltersFor = (
  file: ExtractedFile,
): { name: string; extensions: string[] }[] => {
  const extension = extensionFromFile(file);

  return extension
    ? [{ name: `${extension.toUpperCase()} file`, extensions: [extension] }]
    : [];
};

function App() {
  const [tabs, setTabs] = useState<AnalysisTab[]>([createTab(1)]);
  const [activeTabId, setActiveTabId] = useState<number>(1);
  const nextTabIdRef = useRef(2);

  const activeTab = useMemo(
    () => tabs.find((tab) => tab.id === activeTabId) ?? tabs[0],
    [tabs, activeTabId],
  );

  const canCreateTask = Boolean(
    activeTab?.caseNumber.trim() &&
      activeTab.caseName.trim() &&
      activeTab.investigatorName.trim() &&
      activeTab.date.trim() &&
      !activeTab.taskId &&
      activeTab.phase !== "creating",
  );

  const patchTab = (tabId: number, patch: Partial<AnalysisTab>): void => {
    setTabs((prev) =>
      prev.map((tab) => (tab.id === tabId ? { ...tab, ...patch } : tab)),
    );
  };

  const handleTaskFieldChange = (
    field: TaskFormField,
    value: string,
  ): void => {
    if (!activeTab || activeTab.taskId) {
      return;
    }

    patchTab(activeTab.id, { [field]: value });
  };

  const handleCreateTask = async (): Promise<void> => {
    if (!activeTab || !canCreateTask) {
      return;
    }

    patchTab(activeTab.id, { phase: "creating", error: null });

    try {
      const task = await createTask({
        caseNumber: activeTab.caseNumber,
        caseName: activeTab.caseName,
        investigatorName: activeTab.investigatorName,
        date: activeTab.date,
      });

      patchTab(activeTab.id, {
        taskId: task.taskId,
        title: truncateTitle(`${task.caseNumber} ${task.caseName}`),
        caseNumber: task.caseNumber,
        caseName: task.caseName,
        investigatorName: task.investigatorName,
        date: task.date,
        mediaFile: task.mediaFile,
        extractedFiles: task.extractedFiles,
        result: null,
        downloadPath: null,
        phase: "ready",
        error: null,
      });
    } catch (error) {
      patchTab(activeTab.id, {
        phase: "draft",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  const handleSelectMediaFile = async (): Promise<void> => {
    if (
      !activeTab?.taskId ||
      activeTab.phase === "uploading" ||
      activeTab.phase === "analyzing"
    ) {
      return;
    }

    try {
      const selectedPath = await open({
        multiple: false,
        filters: [
          {
            name: "Media files",
            extensions: [
              "apng",
              "avif",
              "avi",
              "bmp",
              "flac",
              "gif",
              "jpeg",
              "jpg",
              "m4a",
              "m4v",
              "mkv",
              "mov",
              "mp3",
              "mp4",
              "mpeg",
              "ogg",
              "png",
              "wav",
              "weba",
              "webm",
              "webp",
            ],
          },
        ],
      });

      if (!selectedPath || Array.isArray(selectedPath)) {
        return;
      }

      patchTab(activeTab.id, {
        phase: "uploading",
        error: null,
        downloadPath: null,
        mediaFile: null,
        result: null,
        extractedFiles: [],
      });

      const task = await attachMediaFile(activeTab.taskId, selectedPath);

      patchTab(activeTab.id, {
        mediaFile: task.mediaFile,
        extractedFiles: task.extractedFiles,
        phase: "ready",
        error: null,
      });
    } catch (error) {
      patchTab(activeTab.id, {
        phase: "failed",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  const handleAnalyze = async (): Promise<void> => {
    if (!activeTab?.taskId || !activeTab.mediaFile || activeTab.phase === "analyzing") {
      return;
    }

    patchTab(activeTab.id, {
      phase: "analyzing",
      result: null,
      error: null,
      downloadPath: null,
      extractedFiles: [],
    });

    try {
      const result = await analyzeTask(activeTab.taskId);

      patchTab(activeTab.id, {
        phase: "done",
        result,
        extractedFiles: result.extractedFiles,
        error: null,
      });
    } catch (error) {
      patchTab(activeTab.id, {
        phase: "failed",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  const handleDownloadExtractedFile = async (
    file: ExtractedFile,
  ): Promise<void> => {
    if (!activeTab?.taskId) {
      return;
    }

    try {
      const filters = saveFiltersFor(file);
      const targetPath = await save({
        defaultPath: defaultSaveName(file.fileName),
        ...(filters.length > 0 ? { filters } : {}),
      });

      if (!targetPath) {
        return;
      }

      const downloaded = await downloadExtractedFile(
        activeTab.taskId,
        file.id,
        targetPath,
      );
      patchTab(activeTab.id, {
        downloadPath: downloaded.savedPath,
        error: null,
      });
    } catch (error) {
      patchTab(activeTab.id, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  const handleNewTab = (): void => {
    const id = nextTabIdRef.current;
    nextTabIdRef.current += 1;

    setTabs((prev) => [...prev, createTab(id)]);
    setActiveTabId(id);
  };

  const handleDeleteTab = (tabId: number): void => {
    if (tabs.length === 1) {
      return;
    }

    const deleteIndex = tabs.findIndex((tab) => tab.id === tabId);
    const nextTabs = tabs.filter((tab) => tab.id !== tabId);

    if (activeTabId === tabId) {
      const fallbackTab = nextTabs[Math.max(0, deleteIndex - 1)] ?? nextTabs[0];
      if (fallbackTab) {
        setActiveTabId(fallbackTab.id);
      }
    }

    setTabs(nextTabs);
  };

  return (
    <main className="app">
      <header className="hero">
        <p className="eyebrow">StegaScope</p>
        <h1>Steganalysis Workspace</h1>
        <p className="subtitle">
          Create a case task, attach a media file, run analyzers, and review extracted files.
        </p>
      </header>

      <section className="tabs" aria-label="Task tabs">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={`tab-item ${tab.id === activeTabId ? "active" : ""}`}
          >
            <button
              className={`tab ${tab.id === activeTabId ? "active" : ""}`}
              type="button"
              onClick={() => setActiveTabId(tab.id)}
            >
              {tab.title}
            </button>
            {tabs.length > 1 && (
              <button
                className="tab-close"
                type="button"
                onClick={() => handleDeleteTab(tab.id)}
                aria-label={`Delete ${tab.title}`}
                title="Delete tab"
              >
                x
              </button>
            )}
          </div>
        ))}
        <button className="tab add-tab" type="button" onClick={handleNewTab}>
          + New Task
        </button>
      </section>

      {activeTab && (
        <section className="panel workspace">
          {activeTab.phase === "analyzing" ? (
            <section className="analysis-loading-page" aria-live="polite">
              <div className="loading-visual" aria-hidden="true">
                <div className="scan-frame">
                  <div className="scan-surface" />
                  <div className="scan-line" />
                </div>
                <div className="probe" />
              </div>
              <h2>Running Analyzers...</h2>
              <p className="loading-copy">
                File loader output is being checked by the registered analyzer set.
              </p>
              <p className="loading-file">
                Current file: <strong>{activeTab.mediaFile?.fileName ?? "Unknown"}</strong>
              </p>
            </section>
          ) : (
            <>
              <section className="task-form" aria-labelledby="task-form-heading">
                <div className="section-heading">
                  <p className="eyebrow">Task</p>
                  <h2 id="task-form-heading">Case Details</h2>
                  {activeTab.taskId && <span className="status-pill">Created</span>}
                </div>

                <div className="form-grid">
                  <label>
                    Case Number
                    <input
                      value={activeTab.caseNumber}
                      onChange={(event) =>
                        handleTaskFieldChange("caseNumber", event.target.value)
                      }
                      disabled={Boolean(activeTab.taskId)}
                      required
                    />
                  </label>
                  <label>
                    Case Name
                    <input
                      value={activeTab.caseName}
                      onChange={(event) =>
                        handleTaskFieldChange("caseName", event.target.value)
                      }
                      disabled={Boolean(activeTab.taskId)}
                      required
                    />
                  </label>
                  <label>
                    Investigator Name
                    <input
                      value={activeTab.investigatorName}
                      onChange={(event) =>
                        handleTaskFieldChange("investigatorName", event.target.value)
                      }
                      disabled={Boolean(activeTab.taskId)}
                      required
                    />
                  </label>
                  <label>
                    Date
                    <input
                      type="date"
                      value={activeTab.date}
                      onChange={(event) => handleTaskFieldChange("date", event.target.value)}
                      disabled={Boolean(activeTab.taskId)}
                      required
                    />
                  </label>
                </div>

                <div className="actions">
                  <button
                    className="analyze"
                    type="button"
                    onClick={handleCreateTask}
                    disabled={!canCreateTask}
                  >
                    {activeTab.phase === "creating" ? "Creating..." : "Create Task"}
                  </button>
                </div>
              </section>

              {activeTab.taskId && (
                <section className="media-section" aria-labelledby="media-heading">
                  <div className="section-heading">
                    <p className="eyebrow">Media</p>
                    <h2 id="media-heading">File Loader</h2>
                    {activeTab.mediaFile && (
                      <span className="status-pill">Loaded</span>
                    )}
                  </div>

                  <div
                    className={`dropzone ${
                      activeTab.phase === "uploading" || activeTab.phase === "analyzing"
                        ? "busy"
                        : ""
                    }`}
                    onClick={() => void handleSelectMediaFile()}
                    role="button"
                    aria-disabled={
                      activeTab.phase === "uploading" || activeTab.phase === "analyzing"
                    }
                    tabIndex={
                      activeTab.phase === "uploading" || activeTab.phase === "analyzing"
                        ? -1
                        : 0
                    }
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        void handleSelectMediaFile();
                      }
                    }}
                  >
                    <p className="drop-title">
                      {activeTab.phase === "uploading"
                        ? "Loading media file..."
                        : activeTab.phase === "analyzing"
                          ? "Analysis in progress..."
                          : "Select image, audio, or video file"}
                    </p>
                    <p className="muted">No file data leaves this desktop session.</p>
                    {activeTab.mediaFile && (
                      <div className="selected-file">
                        <strong>{activeTab.mediaFile.fileName}</strong>
                        <span>{activeTab.mediaFile.fileType}</span>
                        <span>{formatFileSize(activeTab.mediaFile.fileSizeBytes)}</span>
                      </div>
                    )}
                  </div>

                  <div className="actions">
                    <button
                      className="analyze"
                      type="button"
                      onClick={handleAnalyze}
                      disabled={
                        !activeTab.mediaFile ||
                        activeTab.phase === "uploading" ||
                        activeTab.phase === "analyzing"
                      }
                    >
                      Start Analysis
                    </button>
                  </div>
                </section>
              )}

              {activeTab.error && <p className="error-banner">{activeTab.error}</p>}
              {activeTab.downloadPath && (
                <p className="success-banner">
                  Saved extracted file: <strong>{activeTab.downloadPath}</strong>
                </p>
              )}

              {activeTab.phase === "done" && activeTab.result && (
                <article className="result">
                  <h2>Analysis Result</h2>
                  <p className="result-summary">{activeTab.result.note}</p>
                  <div className="result-grid">
                    <div>
                      <span>Confidence</span>
                      <strong>{(activeTab.result.confidence * 100).toFixed(1)}%</strong>
                    </div>
                    <div>
                      <span>Suspicious Regions</span>
                      <strong>{activeTab.result.suspiciousRegions}</strong>
                    </div>
                    <div>
                      <span>Completed At</span>
                      <strong>{formatCompletedAt(activeTab.result.completedAt)}</strong>
                    </div>
                  </div>

                  <section className="suspicious-files">
                    <div className="suspicious-files-head">
                      <h3>Extracted Files</h3>
                      <span>{activeTab.extractedFiles.length} item(s)</span>
                    </div>
                    {activeTab.extractedFiles.length > 0 ? (
                      <ul>
                        {activeTab.extractedFiles.map((file) => (
                          <li key={file.id}>
                            <span className="file-primary">
                              <strong>{file.fileName}</strong>
                              <small>{file.fileType}</small>
                              <small>Analyzer: {file.analyzerName}</small>
                              <small>
                                Validation: {file.validationStatus} - {file.validationNote}
                              </small>
                              <small>
                                Signature: {file.fileSignature.label}
                                {file.fileSignature.isKnown
                                  ? ` (.${file.fileSignature.extension})`
                                  : " (extension unknown)"}
                              </small>
                              <small>Header: {file.fileSignature.headerHex}</small>
                            </span>
                            <span className={`level level-${file.suspiciousLevel}`}>
                              {file.suspiciousLevel}
                            </span>
                            <span>{formatFileSize(file.fileSizeBytes)}</span>
                            <button
                              className="download-one"
                              type="button"
                              onClick={() => void handleDownloadExtractedFile(file)}
                            >
                              Download
                            </button>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="empty-state">No extracted files were found.</p>
                    )}
                  </section>
                </article>
              )}
            </>
          )}
        </section>
      )}
    </main>
  );
}

export default App;
