import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type BootstrapStatus = {
  appName: string;
  appVersion: string;
  profile: "debug" | "release";
  os: string;
  ready: boolean;
};

function App() {
  const [status, setStatus] = useState<BootstrapStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadStatus = async () => {
      try {
        const result = await invoke<BootstrapStatus>("bootstrap_status");
        setStatus(result);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    };

    loadStatus();
  }, []);

  return (
    <main className="app">
      <header className="hero">
        <p className="eyebrow">Project Bootstrap</p>
        <h1>StegaScope</h1>
        <p className="subtitle">
          The desktop baseline is ready for feature development.
        </p>
      </header>

      <section className="panel">
        <h2>Runtime Status</h2>
        {error && <p className="error">Failed to load Rust status: {error}</p>}
        {!error && !status && <p className="muted">Loading runtime status...</p>}
        {status && (
          <div className="status-grid">
            <article>
              <span>App</span>
              <strong>{status.appName}</strong>
            </article>
            <article>
              <span>Version</span>
              <strong>{status.appVersion}</strong>
            </article>
            <article>
              <span>Profile</span>
              <strong>{status.profile}</strong>
            </article>
            <article>
              <span>OS</span>
              <strong>{status.os}</strong>
            </article>
            <article>
              <span>Ready</span>
              <strong>{status.ready ? "YES" : "NO"}</strong>
            </article>
          </div>
        )}
      </section>

      <section className="panel">
        <h2>First Build Checklist</h2>
        <ul>
          <li>Define the MVP feature scope</li>
          <li>Design domain models and data flow</li>
          <li>Connect file I/O and image processing modules</li>
          <li>Add feature-level tests</li>
        </ul>
      </section>

      <section className="panel">
        <h2>Start Points</h2>
        <p>
          Extend UI in <code>src/</code> and Rust core logic in <code>src-tauri/src/</code>.
        </p>
      </section>
    </main>
  );
}

export default App;
