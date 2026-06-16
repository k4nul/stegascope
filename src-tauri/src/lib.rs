pub mod domain;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use domain::{
    create_loader, default_analyzers, finalize_extracted_payloads, ExtractedFile, MediaFileInfo,
    SuspiciousLevel, Task,
};
use serde::{Deserialize, Serialize};
use tauri::State;

struct AppState {
    tasks: Mutex<HashMap<String, Task>>,
    next_task_number: AtomicU64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            tasks: Mutex::new(HashMap::new()),
            next_task_number: AtomicU64::new(1),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapStatus {
    app_name: String,
    app_version: String,
    profile: String,
    os: String,
    ready: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTaskInput {
    case_number: String,
    case_name: String,
    investigator_name: String,
    date: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadedMediaInput {
    file_name: String,
    file_size_bytes: u64,
    file_type: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadedMediaPathInput {
    file_path: String,
    file_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskResponse {
    task_id: String,
    case_number: String,
    case_name: String,
    investigator_name: String,
    date: String,
    media_file: Option<MediaFileInfo>,
    extracted_files: Vec<ExtractedFile>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisResultResponse {
    task_id: String,
    confidence: f64,
    suspicious_regions: usize,
    note: String,
    completed_at: String,
    extracted_files: Vec<ExtractedFile>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadExtractedFileResponse {
    file_name: String,
    file_type: String,
    saved_path: String,
}

#[tauri::command]
fn bootstrap_status() -> BootstrapStatus {
    BootstrapStatus {
        app_name: env!("CARGO_PKG_NAME").to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        profile: if cfg!(debug_assertions) {
            "debug".to_string()
        } else {
            "release".to_string()
        },
        os: std::env::consts::OS.to_string(),
        ready: true,
    }
}

#[tauri::command]
fn create_task(input: CreateTaskInput, state: State<'_, AppState>) -> Result<TaskResponse, String> {
    create_task_with_state(input, state.inner())
}

fn create_task_with_state(
    input: CreateTaskInput,
    state: &AppState,
) -> Result<TaskResponse, String> {
    validate_required(&input.case_number, "case number")?;
    validate_required(&input.case_name, "case name")?;
    validate_required(&input.investigator_name, "investigator name")?;
    validate_required(&input.date, "date")?;

    let task_id = format!(
        "task-{}",
        state.next_task_number.fetch_add(1, Ordering::Relaxed)
    );
    let task = Task::new(
        input.case_number.trim(),
        input.case_name.trim(),
        input.date.trim(),
        input.investigator_name.trim(),
    );

    let mut tasks = lock_tasks(&state)?;
    tasks.insert(task_id.clone(), task);

    let task = tasks
        .get(&task_id)
        .ok_or_else(|| "created task was not found".to_string())?;

    Ok(task_to_response(&task_id, task))
}

#[tauri::command]
fn attach_media_file(
    task_id: String,
    input: UploadedMediaInput,
    state: State<'_, AppState>,
) -> Result<TaskResponse, String> {
    attach_media_file_with_state(task_id, input, state.inner())
}

fn attach_media_file_with_state(
    task_id: String,
    input: UploadedMediaInput,
    state: &AppState,
) -> Result<TaskResponse, String> {
    validate_required(&task_id, "task id")?;
    validate_required(&input.file_name, "file name")?;

    if input.bytes.is_empty() {
        return Err("media file is empty".to_string());
    }

    let file_size_bytes = if input.file_size_bytes == 0 {
        input.bytes.len() as u64
    } else {
        input.file_size_bytes
    };
    let file_type = normalize_media_type(&input.file_name, &input.file_type);

    attach_media_bytes_with_state(
        &task_id,
        &input.file_name,
        file_size_bytes,
        file_type,
        input.bytes,
        state,
    )
}

#[tauri::command]
fn attach_media_file_from_path(
    task_id: String,
    input: UploadedMediaPathInput,
    state: State<'_, AppState>,
) -> Result<TaskResponse, String> {
    attach_media_file_from_path_with_state(task_id, input, state.inner())
}

fn attach_media_file_from_path_with_state(
    task_id: String,
    input: UploadedMediaPathInput,
    state: &AppState,
) -> Result<TaskResponse, String> {
    validate_required(&task_id, "task id")?;
    validate_required(&input.file_path, "file path")?;

    let path = PathBuf::from(input.file_path.trim());
    let metadata =
        fs::metadata(&path).map_err(|error| format!("failed to inspect media file: {error}"))?;
    if !metadata.is_file() {
        return Err("media path is not a file".to_string());
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "media file name is invalid".to_string())?
        .to_string();
    let bytes = fs::read(&path).map_err(|error| format!("failed to read media file: {error}"))?;
    let file_type = normalize_media_type(&file_name, input.file_type.as_deref().unwrap_or(""));

    attach_media_bytes_with_state(
        &task_id,
        &file_name,
        metadata.len(),
        file_type,
        bytes,
        state,
    )
}

fn attach_media_bytes_with_state(
    task_id: &str,
    file_name: &str,
    file_size_bytes: u64,
    file_type: String,
    bytes: Vec<u8>,
    state: &AppState,
) -> Result<TaskResponse, String> {
    if bytes.is_empty() {
        return Err("media file is empty".to_string());
    }

    let media_info = MediaFileInfo::new(file_name.trim(), file_size_bytes, file_type);
    let loader = create_loader(media_info, bytes).map_err(|error| error.to_string())?;

    let mut tasks = lock_tasks(&state)?;
    let task = tasks
        .get_mut(task_id.trim())
        .ok_or_else(|| format!("task not found: {}", task_id.trim()))?;

    task.set_loader(loader);
    task.clear_extracted_files();

    Ok(task_to_response(task_id.trim(), task))
}

#[tauri::command]
fn analyze_task(
    task_id: String,
    state: State<'_, AppState>,
) -> Result<AnalysisResultResponse, String> {
    analyze_task_with_state(task_id, state.inner())
}

fn analyze_task_with_state(
    task_id: String,
    state: &AppState,
) -> Result<AnalysisResultResponse, String> {
    validate_required(&task_id, "task id")?;

    let mut tasks = lock_tasks(&state)?;
    let task = tasks
        .get_mut(task_id.trim())
        .ok_or_else(|| format!("task not found: {}", task_id.trim()))?;
    let media = task
        .loader()
        .ok_or_else(|| "task does not have a media file attached".to_string())?
        .load()
        .map_err(|error| error.to_string())?;
    let mut extracted_payloads = Vec::new();
    for analyzer in default_analyzers() {
        let outcome = analyzer
            .analyze(&media)
            .map_err(|error| error.to_string())?;
        extracted_payloads.extend(outcome.extracted_payloads);
    }

    task.clear_extracted_files();
    task.replace_extracted_payloads(finalize_extracted_payloads(extracted_payloads));
    let extracted_files = task.extracted_files().to_vec();

    Ok(AnalysisResultResponse {
        task_id: task_id.trim().to_string(),
        confidence: confidence_for(&extracted_files),
        suspicious_regions: extracted_files.len(),
        note: analysis_note(&extracted_files),
        completed_at: completed_at_label(),
        extracted_files,
    })
}

#[tauri::command]
fn get_extracted_files(
    task_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ExtractedFile>, String> {
    get_extracted_files_with_state(task_id, state.inner())
}

fn get_extracted_files_with_state(
    task_id: String,
    state: &AppState,
) -> Result<Vec<ExtractedFile>, String> {
    validate_required(&task_id, "task id")?;

    let tasks = lock_tasks(&state)?;
    let task = tasks
        .get(task_id.trim())
        .ok_or_else(|| format!("task not found: {}", task_id.trim()))?;

    Ok(task.extracted_files().to_vec())
}

#[tauri::command]
fn download_extracted_file(
    task_id: String,
    file_name: String,
    analyzer_name: String,
    target_path: String,
    state: State<'_, AppState>,
) -> Result<DownloadExtractedFileResponse, String> {
    download_extracted_file_with_state(
        task_id,
        file_name,
        analyzer_name,
        target_path,
        state.inner(),
    )
}

fn download_extracted_file_with_state(
    task_id: String,
    file_name: String,
    analyzer_name: String,
    target_path: String,
    state: &AppState,
) -> Result<DownloadExtractedFileResponse, String> {
    validate_required(&task_id, "task id")?;
    validate_required(&file_name, "file name")?;
    validate_required(&analyzer_name, "analyzer name")?;
    validate_required(&target_path, "save path")?;

    let tasks = lock_tasks(&state)?;
    let task = tasks
        .get(task_id.trim())
        .ok_or_else(|| format!("task not found: {}", task_id.trim()))?;
    let payload = task
        .extracted_payloads()
        .iter()
        .find(|payload| {
            payload.file.file_name == file_name && payload.file.analyzer_name == analyzer_name
        })
        .ok_or_else(|| {
            format!(
                "extracted file bytes not found in current analysis result: {file_name} from {analyzer_name}"
            )
        })?;
    let saved_path = save_downloaded_payload(&target_path, &payload.bytes)?;

    Ok(DownloadExtractedFileResponse {
        file_name: payload.file.file_name.clone(),
        file_type: payload.file.file_type.clone(),
        saved_path: saved_path.display().to_string(),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            bootstrap_status,
            create_task,
            attach_media_file,
            attach_media_file_from_path,
            analyze_task,
            get_extracted_files,
            download_extracted_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn lock_tasks(state: &AppState) -> Result<MutexGuard<'_, HashMap<String, Task>>, String> {
    state
        .tasks
        .lock()
        .map_err(|_| "task store lock was poisoned".to_string())
}

fn task_to_response(task_id: &str, task: &Task) -> TaskResponse {
    TaskResponse {
        task_id: task_id.to_string(),
        case_number: task.case_number.clone(),
        case_name: task.case_name.clone(),
        investigator_name: task.investigator_name.clone(),
        date: task.date.clone(),
        media_file: task.loader().map(|loader| loader.media_info().clone()),
        extracted_files: task.extracted_files().to_vec(),
    }
}

fn validate_required(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} is required"));
    }

    Ok(())
}

fn save_downloaded_payload(target_path: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let path = PathBuf::from(target_path.trim());
    if path.as_os_str().is_empty() {
        return Err("save path is required".to_string());
    }

    if path.is_dir() {
        return Err("save path points to a directory".to_string());
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create save directory: {error}"))?;
        }
    }

    fs::write(&path, bytes).map_err(|error| format!("failed to save extracted file: {error}"))?;

    Ok(path)
}

fn normalize_media_type(file_name: &str, file_type: &str) -> String {
    let trimmed_type = file_type.trim();
    if !trimmed_type.is_empty() {
        return trimmed_type.to_string();
    }

    let extension = file_name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    extension_media_type(&extension)
        .unwrap_or("application/octet-stream")
        .to_string()
}

fn extension_media_type(extension: &str) -> Option<&'static str> {
    match extension {
        "apng" => Some("image/apng"),
        "avif" => Some("image/avif"),
        "avi" => Some("video/x-msvideo"),
        "bmp" => Some("image/bmp"),
        "flac" => Some("audio/flac"),
        "gif" => Some("image/gif"),
        "jpeg" | "jpg" => Some("image/jpeg"),
        "m4a" => Some("audio/mp4"),
        "m4v" => Some("video/mp4"),
        "mkv" => Some("video/x-matroska"),
        "mov" => Some("video/quicktime"),
        "mp3" => Some("audio/mpeg"),
        "mp4" => Some("video/mp4"),
        "mpeg" => Some("video/mpeg"),
        "ogg" => Some("audio/ogg"),
        "png" => Some("image/png"),
        "wav" => Some("audio/wav"),
        "weba" => Some("audio/webm"),
        "webm" => Some("video/webm"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

fn confidence_for(extracted_files: &[ExtractedFile]) -> f64 {
    let max_weight = extracted_files
        .iter()
        .map(|file| suspicious_level_weight(&file.suspicious_level))
        .fold(0.12_f64, f64::max);
    let volume_bonus = (extracted_files.len() as f64 * 0.04).min(0.18);

    (max_weight + volume_bonus).min(0.98)
}

fn suspicious_level_weight(level: &SuspiciousLevel) -> f64 {
    match level {
        SuspiciousLevel::Unknown => 0.12,
        SuspiciousLevel::Low => 0.32,
        SuspiciousLevel::Medium => 0.58,
        SuspiciousLevel::High => 0.78,
        SuspiciousLevel::Critical => 0.92,
    }
}

fn analysis_note(extracted_files: &[ExtractedFile]) -> String {
    if extracted_files.is_empty() {
        return "No extracted payload candidates were found.".to_string();
    }

    if extracted_files.iter().any(|file| {
        matches!(
            file.suspicious_level,
            SuspiciousLevel::High | SuspiciousLevel::Critical
        )
    }) {
        return "High-suspicion extracted payload candidates were found.".to_string();
    }

    "Potential side-channel data was extracted for review.".to_string()
}

fn completed_at_label() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();

    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::{ExtractedPayload, FileSignature, PayloadSource, ValidationStatus};
    use image::ImageEncoder;
    use std::path::Path;

    #[test]
    fn save_downloaded_payload_creates_parent_directories_and_writes_bytes() {
        let temp_dir = TempDir::new("writes-nested-payload");
        let target_path = temp_dir.path().join("downloads").join("payload.bin");

        let saved_path = save_downloaded_payload(
            target_path.to_str().expect("target path should be utf-8"),
            b"hidden payload",
        )
        .expect("payload should be saved");

        assert_eq!(saved_path, target_path);
        assert_eq!(
            fs::read(&saved_path).expect("saved payload should be readable"),
            b"hidden payload"
        );
    }

    #[test]
    fn save_downloaded_payload_rejects_blank_path() {
        let error = save_downloaded_payload("   ", b"payload")
            .expect_err("blank save path should be rejected");

        assert_eq!(error, "save path is required");
    }

    #[test]
    fn save_downloaded_payload_rejects_directory_target() {
        let temp_dir = TempDir::new("rejects-directory-target");
        let directory_path = temp_dir.path().join("existing-directory");
        fs::create_dir_all(&directory_path).expect("directory target should be created");

        let error = save_downloaded_payload(
            directory_path
                .to_str()
                .expect("directory path should be utf-8"),
            b"payload",
        )
        .expect_err("directory target should be rejected");

        assert_eq!(error, "save path points to a directory");
        assert!(fs::read_dir(&directory_path)
            .expect("directory should still be readable")
            .next()
            .is_none());
    }

    #[test]
    fn save_downloaded_payload_trims_outer_whitespace_before_saving() {
        let temp_dir = TempDir::new("trims-save-path");
        let target_path = temp_dir.path().join("payload.bin");
        let padded_target_path = format!(
            "  {}  ",
            target_path.to_str().expect("target path should be utf-8")
        );

        let saved_path = save_downloaded_payload(&padded_target_path, b"trimmed path payload")
            .expect("trimmed target path should be saved");

        assert_eq!(saved_path, target_path);
        assert_eq!(
            fs::read(&saved_path).expect("saved payload should be readable"),
            b"trimmed path payload"
        );
    }

    #[test]
    fn normalize_media_type_uses_canonical_extension_fallbacks() {
        let cases = [
            ("evidence.JPG", "image/jpeg"),
            ("carrier.m4a", "audio/mp4"),
            ("recording.wav", "audio/wav"),
            ("capture.avi", "video/x-msvideo"),
            ("clip.mov", "video/quicktime"),
            ("sample.webm", "video/webm"),
        ];

        for (file_name, expected_type) in cases {
            assert_eq!(normalize_media_type(file_name, ""), expected_type);
        }
    }

    #[test]
    fn normalize_media_type_preserves_browser_provided_type() {
        assert_eq!(
            normalize_media_type("carrier.jpg", " image/custom-jpeg "),
            "image/custom-jpeg"
        );
    }

    #[test]
    fn create_task_command_test_trims_required_fields_and_assigns_ids() {
        let state = AppState::default();

        let first = create_task_with_state(
            CreateTaskInput {
                case_number: " CASE-001 ".to_string(),
                case_name: " Synthetic case ".to_string(),
                investigator_name: " Automation ".to_string(),
                date: " 2026-06-15 ".to_string(),
            },
            &state,
        )
        .expect("first task should be created");
        let second =
            create_task_with_state(sample_task_input(), &state).expect("second task should exist");

        assert_eq!(first.task_id, "task-1");
        assert_eq!(first.case_number, "CASE-001");
        assert_eq!(first.case_name, "Synthetic case");
        assert_eq!(first.investigator_name, "Automation");
        assert_eq!(first.date, "2026-06-15");
        assert_eq!(second.task_id, "task-2");
    }

    #[test]
    fn create_task_command_test_rejects_blank_required_fields() {
        let state = AppState::default();
        let error = create_task_with_state(
            CreateTaskInput {
                case_number: "CASE-001".to_string(),
                case_name: "   ".to_string(),
                investigator_name: "Automation".to_string(),
                date: "2026-06-15".to_string(),
            },
            &state,
        )
        .expect_err("blank case name should be rejected");

        assert_eq!(error, "case name is required");
    }

    #[test]
    fn attach_media_file_command_test_attaches_media_and_normalizes_type() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let png_bytes = png_image_bytes();

        let response = attach_media_file_with_state(
            task.task_id,
            UploadedMediaInput {
                file_name: "carrier.png".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: png_bytes.clone(),
            },
            &state,
        )
        .expect("media file should attach");
        let media_file = response
            .media_file
            .expect("attached media should be returned");

        assert_eq!(media_file.file_name, "carrier.png");
        assert_eq!(media_file.file_size_bytes, png_bytes.len() as u64);
        assert_eq!(media_file.file_type, "image/png");
        assert!(response.extracted_files.is_empty());
    }

    #[test]
    fn attach_media_file_from_path_command_test_reads_local_media_path() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let temp_dir = TempDir::new("path-media-attach");
        let media_path = temp_dir.path().join("carrier.png");
        let media_bytes = png_image_bytes();
        fs::write(&media_path, &media_bytes).expect("media fixture should be written");

        let response = attach_media_file_from_path_with_state(
            task.task_id,
            UploadedMediaPathInput {
                file_path: media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect("media file path should attach");
        let media_file = response
            .media_file
            .expect("attached path media should be returned");

        assert_eq!(media_file.file_name, "carrier.png");
        assert_eq!(media_file.file_size_bytes, media_bytes.len() as u64);
        assert_eq!(media_file.file_type, "image/png");
        assert!(response.extracted_files.is_empty());
    }

    #[test]
    fn analyze_task_command_test_runs_default_analyzers_and_stores_result() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;

        attach_media_file_with_state(
            task_id.clone(),
            UploadedMediaInput {
                file_name: "carrier.png".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: png_image_bytes(),
            },
            &state,
        )
        .expect("media file should attach");

        let result = analyze_task_with_state(task_id.clone(), &state).expect("analysis should run");
        let stored_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("stored analysis result should be readable");

        assert_eq!(result.task_id, task_id);
        assert_eq!(result.confidence, 0.12);
        assert_eq!(result.suspicious_regions, 0);
        assert_eq!(result.note, "No extracted payload candidates were found.");
        assert!(result.completed_at.starts_with("unix:"));
        assert!(result.extracted_files.is_empty());
        assert!(stored_files.is_empty());
    }

    #[test]
    fn get_extracted_files_command_test_returns_current_result_metadata() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let extracted_file = sample_extracted_file("stored-note.pdf", "unit-test-analyzer");

        {
            let mut tasks = lock_tasks(&state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(&task.task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![ExtractedPayload {
                file: extracted_file.clone(),
                bytes: b"stored payload".to_vec(),
                source: PayloadSource::SignatureScan,
            }]);
        }

        let stored_files = get_extracted_files_with_state(task.task_id, &state)
            .expect("stored extracted files should be readable");

        assert_eq!(stored_files, vec![extracted_file]);
    }

    #[test]
    fn download_extracted_file_command_test_writes_current_payload_bytes() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let payload_bytes = b"downloaded payload bytes".to_vec();
        let extracted_file = sample_extracted_file("downloaded-note.pdf", "unit-test-analyzer");

        {
            let mut tasks = lock_tasks(&state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(&task.task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![ExtractedPayload {
                file: extracted_file,
                bytes: payload_bytes.clone(),
                source: PayloadSource::SignatureScan,
            }]);
        }

        let temp_dir = TempDir::new("downloads-current-payload");
        let target_path = temp_dir.path().join("exports").join("downloaded-note.pdf");
        let response = download_extracted_file_with_state(
            task.task_id,
            "downloaded-note.pdf".to_string(),
            "unit-test-analyzer".to_string(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("payload should download");

        assert_eq!(response.file_name, "downloaded-note.pdf");
        assert_eq!(response.file_type, "application/pdf");
        assert_eq!(response.saved_path, target_path.display().to_string());
        assert_eq!(
            fs::read(&target_path).expect("downloaded payload should be readable"),
            payload_bytes
        );
    }

    #[test]
    fn download_extracted_file_command_test_rejects_missing_payload_bytes() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let temp_dir = TempDir::new("rejects-missing-payload");
        let target_path = temp_dir.path().join("missing.bin");

        let error = download_extracted_file_with_state(
            task.task_id,
            "missing.bin".to_string(),
            "unit-test-analyzer".to_string(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("missing payload should be rejected");

        assert_eq!(
            error,
            "extracted file bytes not found in current analysis result: missing.bin from unit-test-analyzer"
        );
        assert!(!target_path.exists());
    }

    fn sample_task_input() -> CreateTaskInput {
        CreateTaskInput {
            case_number: "CASE-001".to_string(),
            case_name: "Synthetic dependency validation".to_string(),
            investigator_name: "Automation".to_string(),
            date: "2026-06-12".to_string(),
        }
    }

    fn png_image_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        let pixels = [0_u8, 0, 0, 255];
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(&pixels, 1, 1, image::ExtendedColorType::Rgba8)
            .expect("test PNG should encode");
        bytes
    }

    fn sample_extracted_file(file_name: &str, analyzer_name: &str) -> ExtractedFile {
        ExtractedFile::new(
            file_name,
            analyzer_name,
            SuspiciousLevel::High,
            ValidationStatus::Validated,
            "Synthetic command-level payload.",
            24,
            "application/pdf",
            FileSignature::known("PDF document", "pdf", "application/pdf", "25504446"),
        )
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(test_name: &str) -> Self {
            let unique_id = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "stegascope-{test_name}-{}-{unique_id}",
                std::process::id()
            ));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
