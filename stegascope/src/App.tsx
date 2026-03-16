import { useMemo, useRef, useState } from "react";
import "./App.css";

type AnalysisPhase = "idle" | "ready" | "loading" | "done";

type AnalysisResult = {
  confidence: number;
  suspiciousRegions: number;
  note: string;
  completedAt: string;
};

type AnalysisTab = {
  id: number;
  title: string;
  fileName: string | null;
  phase: AnalysisPhase;
  result: AnalysisResult | null;
};

const createTab = (id: number): AnalysisTab => ({
  id,
  title: `Task ${id}`,
  fileName: null,
  phase: "idle",
  result: null,
});

const mockAnalyze = async (): Promise<AnalysisResult> => {
  await new Promise((resolve) => setTimeout(resolve, 1800));
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
  };
};

function App() {
  const [tabs, setTabs] = useState<AnalysisTab[]>([createTab(1)]);
  const [activeTabId, setActiveTabId] = useState<number>(1);
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
      phase: "ready",
      result: null,
      title: file.name.length > 18 ? `${file.name.slice(0, 18)}...` : file.name,
    });
  };

  const handleAnalyze = async () => {
    if (!activeTab || activeTab.phase !== "ready") {
      return;
    }

    patchTab(activeTab.id, { phase: "loading", result: null });
    const result = await mockAnalyze();
    patchTab(activeTab.id, { phase: "done", result });
  };

  const handleNewTab = () => {
    const id = nextTabIdRef.current;
    nextTabIdRef.current += 1;

    setTabs((prev) => [...prev, createTab(id)]);
    setActiveTabId(id);
  };

  return (
    <main className="app">
      <header className="hero">
        <p className="eyebrow">StegaScope</p>
        <h1>Steganalysis Workspace</h1>
        <p className="subtitle">
          Upload a target file, run analysis, and manage multiple tasks in tabs.
        </p>
      </header>

      <section className="tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`tab ${tab.id === activeTabId ? "active" : ""}`}
            type="button"
            onClick={() => setActiveTabId(tab.id)}
          >
            {tab.title}
          </button>
        ))}
        <button className="tab add-tab" type="button" onClick={handleNewTab}>
          + New Tab
        </button>
      </section>

      {activeTab && (
        <section className="panel workspace">
          <div
            className={`dropzone ${activeTab.phase === "loading" ? "disabled" : ""}`}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              const file = event.dataTransfer.files?.[0];
              if (file && activeTab.phase !== "loading") {
                handleFileSelected(file);
              }
            }}
            onClick={() => {
              if (activeTab.phase !== "loading") {
                fileInputRef.current?.click();
              }
            }}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => {
              if (
                (event.key === "Enter" || event.key === " ") &&
                activeTab.phase !== "loading"
              ) {
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
              disabled={activeTab.phase !== "ready"}
            >
              Start Analysis
            </button>
          </div>

          {activeTab.phase === "loading" && (
            <div className="loading-state">
              <div className="spinner" />
              <p>Analyzing file...</p>
            </div>
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
                  <strong>{activeTab.result.completedAt}</strong>
                </div>
              </div>
            </article>
          )}
        </section>
      )}
    </main>
  );
}

export default App;
