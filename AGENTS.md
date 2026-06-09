schema_version: "1.0"
project:
  id: "stegascope"
  type: "desktop.tauri"
  status: "direction-pending"
stack:
  frontend:
    framework: "React"
    bundler: "Vite"
    language: "TypeScript"
    entrypoints:
      - "src/main.tsx"
      - "src/App.tsx"
  backend:
    framework: "Tauri"
    language: "Rust"
    manifest: "src-tauri/Cargo.toml"
  app_shell:
    config: "src-tauri/tauri.conf.json"
scope:
  owns:
    - "src/"
    - "src-tauri/"
    - "public/"
    - "docs/"
  excludes:
    devops_automation_group:
      path: "../devops"
      rule: "do not include in active automation until product direction is selected"
instructions:
  edit_policy:
    preserve_tauri_v2_structure: true
    keep_frontend_and_rust_boundaries_clear: true
    avoid_automation_activation: true
    avoid_product_direction_lock_in: true
  validation:
    manual:
      - command: "npm run build"
        when: "frontend or Vite config changes"
      - command: "cargo check --manifest-path src-tauri/Cargo.toml"
        when: "Rust or Tauri backend changes"
      - command: "npm run tauri -- build"
        when: "release packaging is requested"
automation:
  prepared: true
  enabled: false
  activation_gate:
    required_decision: "product direction"
    required_update: ".codex/automation.yaml:automation.enabled=true"
  disabled_behavior:
    scheduled_runs: false
    ci_runs: false
    release_runs: false
