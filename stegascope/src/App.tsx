import { useMemo, useRef, useState } from "react";
import {
  createAnalysisJob,
  downloadSuspiciousFile as downloadSuspiciousFileApi,
  getAnalysisJobStatus,
  getAnalysisResult,
} from "./api/analysis";
import "./App.css";

type AnalysisPhase = "idle" | "ready" | "loading" | "done" | "failed";

type AnalysisResult = {
  confidence: number;
  suspiciousRegions: number;
  note: string;
  completedAt: string;
  suspiciousFiles: string[];
};

type AnalysisTab = {
  id: number;
  title: string;
  fileName: string | null;
  selectedFile: File | null;
  jobId: string | null;
  progress: number | null;
  phase: AnalysisPhase;
  error: string | null;
  result: AnalysisResult | null;
};

const createTab = (id: number): AnalysisTab => ({
  id,
  title: `Task ${id}`,
  fileName: null,
  selectedFile: null,
  jobId: null,
  progress: null,
  phase: "idle",
  error: null,
  result: null,
});

const sleep = async (ms: number) => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

const mockAnalyze = async (): Promise<AnalysisResult> => {
  await sleep(1800);
  const confidence = 0.72 + Math.random() * 0.22;
  const suspiciousRegions = Math.floor(2 + Math.random() * 5);

  return {
    confidence,
    suspiciousRegions,
    note:
      confidence > 0.9
        ? "High probability of steganographic payload."
        : "Potential hidden payload detected. Additional checks are recommended.",
    completedAt: new Date().toLocaleString(),
    suspiciousFiles: [
      "payload_candidate_01.bin",
      "embedded_stream_alpha.dat",
      "metadata_fragment_hidden.txt",
    ],
  };
};

function App() {
  const [tabs, setTabs] = useState<AnalysisTab[]>([createTab(1)]);
  const [activeTabId, setActiveTabId] = useState<number>(1);
  const [showSuspiciousFiles, setShowSuspiciousFiles] = useState(false);
  const nextTabIdRef = useRef(2);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const activeTab = useMemo(
    () => tabs.find((tab) => tab.id === activeTabId) ?? tabs[0],
    [tabs, activeTabId],
  );

  const patchTab = (tabId: number, patch: Partial<AnalysisTab>) => {
    setTabs((prev) =>
      prev.map((tab) => (tab.id === tabId ? { ...tab, ...patch } : tab)),
    );
  };

  const handleFileSelected = (file: File) => {
    if (!activeTab) {
      return;
    }

    patchTab(activeTab.id, {
      fileName: file.name,
      selectedFile: file,
      phase: "ready",
      progress: null,
      error: null,
      jobId: null,
      result: null,
      title: file.name.length > 18 ? `${file.name.slice(0, 18)}...` : file.name,
    });
    setShowSuspiciousFiles(false);
  };

  const handleAnalyze = async () => {
    if (!activeTab || !activeTab.selectedFile || activeTab.phase === "loading") {
      return;
    }

    patchTab(activeTab.id, {
      phase: "loading",
      result: null,
      error: null,
      progress: 0,
      jobId: null,
    });
    setShowSuspiciousFiles(false);

    try {
      const { jobId } = await createAnalysisJob(activeTab.selectedFile);
      patchTab(activeTab.id, { jobId, progress: 5 });

      let status: Awaited<ReturnType<typeof getAnalysisJobStatus>>;
      while (true) {
        status = await getAnalysisJobStatus(jobId);

        if (status.status === "failed") {
          throw new Error(status.error ?? "Analysis failed in backend.");
        }

        if (status.status === "done") {
          break;
        }

        patchTab(activeTab.id, {
          progress: typeof status.progress === "number" ? status.progress : null,
        });

        await sleep(900);
      }

      const result = await getAnalysisResult(jobId);
      patchTab(activeTab.id, {
        phase: "done",
        progress: 100,
        error: null,
        result: {
          confidence: result.confidence,
          suspiciousRegions: result.suspiciousRegions,
          note: result.note,
          completedAt: result.completedAt ?? new Date().toLocaleString(),
          suspiciousFiles: result.suspiciousFiles ?? [],
        },
      });
    } catch (error) {
      patchTab(activeTab.id, {
        phase: "failed",
        error: error instanceof Error ? error.message : String(error),
        progress: null,
      });
    }
  };

  const handleTestLoading = async () => {
    if (!activeTab || activeTab.phase === "loading") {
      return;
    }

    patchTab(activeTab.id, {
      fileName: activeTab.fileName ?? "test-sample.png",
      phase: "loading",
      result: null,
      error: null,
      progress: null,
      jobId: null,
    });
    setShowSuspiciousFiles(false);
    const result = await mockAnalyze();
    patchTab(activeTab.id, { phase: "done", result, progress: 100 });
  };

  const handleNewTab = () => {
    const id = nextTabIdRef.current;
    nextTabIdRef.current += 1;

    setTabs((prev) => [...prev, createTab(id)]);
    setActiveTabId(id);
    setShowSuspiciousFiles(false);
  };

  const handleDeleteTab = (tabId: number) => {
    setTabs((prev) => {
      if (prev.length === 1) {
        return prev;
      }

      const deleteIndex = prev.findIndex((tab) => tab.id === tabId);
      const nextTabs = prev.filter((tab) => tab.id !== tabId);

      if (activeTabId === tabId) {
        const fallbackTab = nextTabs[Math.max(0, deleteIndex - 1)] ?? nextTabs[0];
        if (fallbackTab) {
          setActiveTabId(fallbackTab.id);
          setShowSuspiciousFiles(false);
        }
      }

      return nextTabs;
    });
  };

  const handleDownloadSuspiciousFile = async (fileName: string) => {
    if (!activeTab?.jobId) {
      return;
    }

    try {
      await downloadSuspiciousFileApi(activeTab.jobId, fileName);
    } catch (error) {
      patchTab(activeTab.id, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  };

  const handleDownloadAllSuspiciousFiles = async () => {
    if (!activeTab?.result) {
      return;
    }

    for (const fileName of activeTab.result.suspiciousFiles) {
      await handleDownloadSuspiciousFile(fileName);
    }
  };

  return (
    <main className="app">
      <header className="hero">
        <p className="eyebrow">StegaScope</p>
        <h1>Steganalysis Workspace</h1>
        <p className="subtitle">
          Upload a target file, run analysis, and manage multiple tasks in tabs.
        </p>
        <button className="test-button" type="button" onClick={handleTestLoading}>
          Test Loading View
        </button>
      </header>

      <section className="tabs">
        {tabs.map((tab) => (
          <div
            key={tab.id}
            className={`tab-item ${tab.id === activeTabId ? "active" : ""}`}
          >
            <button
              className={`tab ${tab.id === activeTabId ? "active" : ""}`}
              type="button"
              onClick={() => {
                setActiveTabId(tab.id);
                setShowSuspiciousFiles(false);
              }}
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
          + New Tab
        </button>
      </section>

      {activeTab && (
        <section className="panel workspace">
          {activeTab.phase === "loading" ? (
            <section className="analysis-loading-page" aria-live="polite">
              <div className="loading-visual" aria-hidden="true">
                <div className="scan-frame">
                  <div className="scan-surface" />
                  <div className="scan-line" />
                  <div className="drift-orb orb-1" />
                  <div className="drift-orb orb-2" />
                  <div className="drift-orb orb-3" />
                </div>
                <div className="probe" />
              </div>
              <h2>Analyzing Target...</h2>
              <p className="loading-copy">
                Pattern signatures and hidden payload traces are being scanned.
              </p>
              <p className="loading-file">
                Current file: <strong>{activeTab.fileName ?? "Unknown"}</strong>
              </p>
              <p className="loading-progress">
                Progress: {typeof activeTab.progress === "number" ? `${activeTab.progress}%` : "Preparing..."}
              </p>
            </section>
          ) : (
            <>
              <div
                className="dropzone"
                onDragOver={(event) => event.preventDefault()}
                onDrop={(event) => {
                  event.preventDefault();
                  const file = event.dataTransfer.files?.[0];
                  if (file) {
                    handleFileSelected(file);
                  }
                }}
                onClick={() => fileInputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    fileInputRef.current?.click();
                  }
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  hidden
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) {
                      handleFileSelected(file);
                    }
                  }}
                />
                <p className="drop-title">Drop analysis target file here</p>
                <p className="muted">or click to select a file from your device</p>
                {activeTab.fileName && (
                  <p className="selected-file">
                    Selected file: <strong>{activeTab.fileName}</strong>
                  </p>
                )}
              </div>

              <div className="actions">
                <button
                  className="analyze"
                  type="button"
                  onClick={handleAnalyze}
                  disabled={!activeTab.selectedFile}
                >
                  Start Analysis
                </button>
              </div>

              {activeTab.error && <p className="error-banner">{activeTab.error}</p>}

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
                      <strong>{activeTab.result.completedAt}</strong>
                    </div>
                  </div>
                  <div className="result-actions">
                    <button
                      className="inspect-button"
                      type="button"
                      onClick={() => setShowSuspiciousFiles((prev) => !prev)}
                    >
                      {showSuspiciousFiles
                        ? "Hide Suspicious Files"
                        : "Inspect Suspicious Files"}
                    </button>
                  </div>
                  {showSuspiciousFiles && (
                    <section className="suspicious-files">
                      <div className="suspicious-files-head">
                        <h3>Suspicious File Candidates</h3>
                        <button
                          className="download-all"
                          type="button"
                          onClick={handleDownloadAllSuspiciousFiles}
                        >
                          Download All
                        </button>
                      </div>
                      <ul>
                        {activeTab.result.suspiciousFiles.map((file) => (
                          <li key={file}>
                            <span>{file}</span>
                            <button
                              className="download-one"
                              type="button"
                              onClick={() => handleDownloadSuspiciousFile(file)}
                            >
                              Download
                            </button>
                          </li>
                        ))}
                      </ul>
                    </section>
                  )}
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
