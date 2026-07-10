pub mod domain;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use domain::{
    create_loader, default_analyzers, ExtractedFile, MediaFileInfo, SuspiciousLevel, Task,
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

    ensure_task_exists(&task_id, state)?;

    let file_type = normalize_media_type(&input.file_name, &input.file_type);

    attach_media_bytes_with_state(
        &task_id,
        &input.file_name,
        input.bytes.len() as u64,
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
    ensure_task_exists(&task_id, state)?;

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
        bytes.len() as u64,
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

fn ensure_task_exists(task_id: &str, state: &AppState) -> Result<(), String> {
    let tasks = lock_tasks(state)?;
    if tasks.contains_key(task_id.trim()) {
        Ok(())
    } else {
        Err(format!("task not found: {}", task_id.trim()))
    }
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
    task.replace_extracted_payloads(extracted_payloads);
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
    file_id: String,
    target_path: String,
    state: State<'_, AppState>,
) -> Result<DownloadExtractedFileResponse, String> {
    download_extracted_file_with_state(task_id, file_id, target_path, state.inner())
}

fn download_extracted_file_with_state(
    task_id: String,
    file_id: String,
    target_path: String,
    state: &AppState,
) -> Result<DownloadExtractedFileResponse, String> {
    validate_required(&task_id, "task id")?;
    validate_required(&file_id, "file id")?;
    validate_required(&target_path, "save path")?;
    let file_id = file_id.trim();

    let (file_name, file_type, bytes) = {
        let tasks = lock_tasks(&state)?;
        let task = tasks
            .get(task_id.trim())
            .ok_or_else(|| format!("task not found: {}", task_id.trim()))?;
        let payload = task
            .extracted_payloads()
            .iter()
            .find(|payload| payload.file.id == file_id)
            .ok_or_else(|| {
                format!("extracted file bytes not found in current analysis result: {file_id}")
            })?;

        (
            payload.file.file_name.clone(),
            payload.file.file_type.clone(),
            payload.bytes.clone(),
        )
    };
    let saved_path = save_downloaded_payload(&target_path, &bytes)?;

    Ok(DownloadExtractedFileResponse {
        file_name,
        file_type,
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
    use sha2::{Digest, Sha256};
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
    fn attach_media_file_command_test_uses_attached_bytes_for_media_size() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let png_bytes = png_image_bytes();

        let response = attach_media_file_with_state(
            task.task_id,
            UploadedMediaInput {
                file_name: "carrier.png".to_string(),
                file_size_bytes: 1,
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
    fn attach_media_file_command_test_rejects_invalid_byte_inputs() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");

        let blank_task_id_error = attach_media_file_with_state(
            "   ".to_string(),
            UploadedMediaInput {
                file_name: "carrier.png".to_string(),
                file_size_bytes: 4,
                file_type: "image/png".to_string(),
                bytes: vec![1, 2, 3, 4],
            },
            &state,
        )
        .expect_err("blank task id should be rejected");
        assert_eq!(blank_task_id_error, "task id is required");

        let blank_file_name_error = attach_media_file_with_state(
            task.task_id.clone(),
            UploadedMediaInput {
                file_name: "   ".to_string(),
                file_size_bytes: 4,
                file_type: "image/png".to_string(),
                bytes: vec![1, 2, 3, 4],
            },
            &state,
        )
        .expect_err("blank file name should be rejected");
        assert_eq!(blank_file_name_error, "file name is required");

        let empty_file_error = attach_media_file_with_state(
            task.task_id.clone(),
            UploadedMediaInput {
                file_name: "empty.png".to_string(),
                file_size_bytes: 0,
                file_type: "image/png".to_string(),
                bytes: Vec::new(),
            },
            &state,
        )
        .expect_err("empty byte upload should be rejected");
        assert_eq!(empty_file_error, "media file is empty");

        let unsupported_type_error = attach_media_file_with_state(
            task.task_id,
            UploadedMediaInput {
                file_name: "carrier.bin".to_string(),
                file_size_bytes: 4,
                file_type: String::new(),
                bytes: vec![1, 2, 3, 4],
            },
            &state,
        )
        .expect_err("unknown binary media type should be rejected");
        assert_eq!(
            unsupported_type_error,
            "unsupported media type for loader: application/octet-stream"
        );
    }

    #[test]
    fn attach_media_file_command_test_rejects_missing_task_before_loader_validation() {
        let state = AppState::default();

        let error = attach_media_file_with_state(
            "task-missing".to_string(),
            UploadedMediaInput {
                file_name: "carrier.bin".to_string(),
                file_size_bytes: 4,
                file_type: String::new(),
                bytes: vec![1, 2, 3, 4],
            },
            &state,
        )
        .expect_err("missing task should be rejected before media loader validation");

        assert_eq!(error, "task not found: task-missing");
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
    fn attach_media_file_from_path_command_test_rejects_invalid_paths() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let temp_dir = TempDir::new("path-media-attach-invalid");

        let blank_path_error = attach_media_file_from_path_with_state(
            task.task_id.clone(),
            UploadedMediaPathInput {
                file_path: "   ".to_string(),
                file_type: None,
            },
            &state,
        )
        .expect_err("blank media path should be rejected");
        assert_eq!(blank_path_error, "file path is required");

        let missing_path = temp_dir.path().join("missing.png");
        let missing_path_error = attach_media_file_from_path_with_state(
            task.task_id.clone(),
            UploadedMediaPathInput {
                file_path: missing_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect_err("missing media path should be rejected");
        assert!(
            missing_path_error.starts_with("failed to inspect media file:"),
            "unexpected missing path error: {missing_path_error}"
        );

        let directory_error = attach_media_file_from_path_with_state(
            task.task_id.clone(),
            UploadedMediaPathInput {
                file_path: temp_dir.path().display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect_err("directory media path should be rejected");
        assert_eq!(directory_error, "media path is not a file");

        let empty_media_path = temp_dir.path().join("empty.png");
        fs::write(&empty_media_path, []).expect("empty media fixture should be written");
        let empty_file_error = attach_media_file_from_path_with_state(
            task.task_id,
            UploadedMediaPathInput {
                file_path: empty_media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect_err("empty path media file should be rejected");
        assert_eq!(empty_file_error, "media file is empty");
    }

    #[test]
    fn attach_media_file_from_path_command_test_rejects_missing_task_before_path_inspection() {
        let state = AppState::default();
        let temp_dir = TempDir::new("path-media-missing-task");
        let missing_path = temp_dir.path().join("missing-carrier.png");

        let error = attach_media_file_from_path_with_state(
            "task-missing".to_string(),
            UploadedMediaPathInput {
                file_path: missing_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect_err("missing task should be rejected before inspecting the local path");

        assert_eq!(error, "task not found: task-missing");
    }

    #[test]
    fn attach_media_file_from_path_command_test_clears_current_result_on_reattach() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let temp_dir = TempDir::new("path-media-reattach-clears-result");
        let first_payload = b"%PDF-1.7\npath reattach stale payload\n%%EOF\n";
        let first_packet = stegascope_packet("path-reattach-note.pdf", first_payload);
        let first_media_path = temp_dir.path().join("first-carrier.png");
        let second_media_path = temp_dir.path().join("second-carrier.png");

        fs::write(
            &first_media_path,
            png_with_text_chunks(&[(b"Comment".as_slice(), first_packet.as_slice())]),
        )
        .expect("first media fixture should be written");
        fs::write(&second_media_path, png_image_bytes())
            .expect("second media fixture should be written");

        attach_media_file_from_path_with_state(
            task_id.clone(),
            UploadedMediaPathInput {
                file_path: first_media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect("first path media file should attach");
        analyze_task_with_state(task_id.clone(), &state).expect("first analysis should run");
        let stale_file_id = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("first analysis result should be readable")
            .first()
            .expect("first analysis should expose a payload")
            .id
            .clone();

        attach_media_file_from_path_with_state(
            task_id.clone(),
            UploadedMediaPathInput {
                file_path: second_media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect("second path media file should attach");
        assert!(get_extracted_files_with_state(task_id.clone(), &state)
            .expect("path reattach should leave result metadata readable")
            .is_empty());

        let stale_target = temp_dir.path().join("stale.pdf");
        let error = download_extracted_file_with_state(
            task_id,
            stale_file_id.clone(),
            stale_target
                .to_str()
                .expect("stale target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("stale path-reattach payload id should be rejected");

        assert_eq!(
            error,
            format!("extracted file bytes not found in current analysis result: {stale_file_id}")
        );
        assert!(!stale_target.exists());
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
    fn analyze_task_command_test_reads_path_attached_jpeg_segment_payload() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let temp_dir = TempDir::new("path-jpeg-segment-analysis");
        let secret = b"%PDF-1.7\npath-attached JPEG segment payload\n%%EOF\n";
        let packet = stegascope_packet("path-jpeg-note.pdf", secret);
        let carrier_bytes = jpeg_image_with_comment_segment(&packet);
        let media_path = temp_dir.path().join("path-segment-carrier.jpg");
        fs::write(&media_path, &carrier_bytes).expect("JPEG media fixture should be written");

        let attach_response = attach_media_file_from_path_with_state(
            task_id.clone(),
            UploadedMediaPathInput {
                file_path: media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect("path-attached JPEG media should attach");
        let media_file = attach_response
            .media_file
            .expect("path-attached JPEG metadata should be returned");
        assert_eq!(media_file.file_name, "path-segment-carrier.jpg");
        assert_eq!(media_file.file_size_bytes, carrier_bytes.len() as u64);
        assert_eq!(media_file.file_type, "image/jpeg");

        let result =
            analyze_task_with_state(task_id.clone(), &state).expect("JPEG analysis should run");
        let stored_files = get_extracted_files_with_state(task_id, &state)
            .expect("stored path-attached JPEG metadata should be readable");
        assert_eq!(result.extracted_files, stored_files);
        assert_eq!(stored_files.len(), 1);

        let file = stored_files
            .iter()
            .find(|file| file.file_name == "path-jpeg-note.pdf")
            .expect("path-attached JPEG segment payload should be extracted");

        assert!(file.id.starts_with("payload-"));
        assert_eq!(file.analyzer_name, "jpeg-segment-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.file_size_bytes, secret.len() as u64);
        assert_eq!(file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(file.validation_status, ValidationStatus::Verified);
        assert_eq!(
            result.note,
            "High-suspicion extracted payload candidates were found."
        );
    }

    #[test]
    fn analyze_task_command_test_reads_path_attached_jpeg_after_eoi_payload() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let temp_dir = TempDir::new("path-jpeg-after-eoi-analysis");
        let secret = b"%PDF-1.7\npath-attached JPEG after-EOI payload\n%%EOF\n";
        let packet = stegascope_packet("path-after-eoi-note.pdf", secret);
        let carrier_bytes = jpeg_image_with_after_eoi_payload(&packet);
        let media_path = temp_dir.path().join("path-after-eoi-carrier.jpg");
        fs::write(&media_path, &carrier_bytes).expect("JPEG media fixture should be written");

        let attach_response = attach_media_file_from_path_with_state(
            task_id.clone(),
            UploadedMediaPathInput {
                file_path: media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect("path-attached JPEG media should attach");
        let media_file = attach_response
            .media_file
            .expect("path-attached JPEG metadata should be returned");
        assert_eq!(media_file.file_name, "path-after-eoi-carrier.jpg");
        assert_eq!(media_file.file_size_bytes, carrier_bytes.len() as u64);
        assert_eq!(media_file.file_type, "image/jpeg");

        let result =
            analyze_task_with_state(task_id.clone(), &state).expect("JPEG analysis should run");
        let stored_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("stored path-attached JPEG metadata should be readable");
        assert_eq!(result.extracted_files, stored_files);
        assert_eq!(stored_files.len(), 1);

        let file = stored_files
            .iter()
            .find(|file| file.file_name == "path-after-eoi-note.pdf")
            .expect("path-attached JPEG after-EOI packet payload should be extracted");

        assert!(file.id.starts_with("payload-"));
        assert_eq!(file.analyzer_name, "jpeg-segment-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.file_size_bytes, secret.len() as u64);
        assert_eq!(file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(file.validation_status, ValidationStatus::Verified);

        let target_path = temp_dir.path().join("downloads").join("after-eoi.pdf");
        download_extracted_file_with_state(
            task_id,
            file.id.clone(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("path-attached after-EOI payload should download");
        assert_eq!(
            fs::read(&target_path).expect("downloaded payload should be readable"),
            secret
        );
    }

    #[test]
    fn analyze_task_command_test_reads_path_attached_png_after_iend_payload() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let temp_dir = TempDir::new("path-png-after-iend-analysis");
        let secret = b"%PDF-1.7\npath-attached PNG after-IEND payload\n%%EOF\n";
        let packet = stegascope_packet("path-after-iend-note.pdf", secret);
        let carrier_bytes = png_with_after_iend_payload(&packet);
        let media_path = temp_dir.path().join("path-after-iend-carrier.png");
        fs::write(&media_path, &carrier_bytes).expect("PNG media fixture should be written");

        let attach_response = attach_media_file_from_path_with_state(
            task_id.clone(),
            UploadedMediaPathInput {
                file_path: media_path.display().to_string(),
                file_type: None,
            },
            &state,
        )
        .expect("path-attached PNG media should attach");
        let media_file = attach_response
            .media_file
            .expect("path-attached PNG metadata should be returned");
        assert_eq!(media_file.file_name, "path-after-iend-carrier.png");
        assert_eq!(media_file.file_size_bytes, carrier_bytes.len() as u64);
        assert_eq!(media_file.file_type, "image/png");

        let result =
            analyze_task_with_state(task_id.clone(), &state).expect("PNG analysis should run");
        let stored_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("stored path-attached PNG metadata should be readable");
        assert_eq!(result.extracted_files, stored_files);
        assert_eq!(stored_files.len(), 1);

        let file = stored_files
            .iter()
            .find(|file| file.file_name == "path-after-iend-note.pdf")
            .expect("path-attached PNG after-IEND packet payload should be extracted");

        assert!(file.id.starts_with("payload-"));
        assert_eq!(file.analyzer_name, "png-container-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.file_size_bytes, secret.len() as u64);
        assert_eq!(file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(file.validation_status, ValidationStatus::Verified);

        let target_path = temp_dir.path().join("downloads").join("after-iend.pdf");
        download_extracted_file_with_state(
            task_id,
            file.id.clone(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("path-attached after-IEND payload should download");
        assert_eq!(
            fs::read(&target_path).expect("downloaded payload should be readable"),
            secret
        );
    }

    #[test]
    fn analyze_task_command_test_rejects_missing_task_or_media() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");

        let blank_task_id_error = analyze_task_with_state("   ".to_string(), &state)
            .expect_err("blank task id should be rejected");
        assert_eq!(blank_task_id_error, "task id is required");

        let missing_task_error = analyze_task_with_state("task-missing".to_string(), &state)
            .expect_err("missing task should be rejected");
        assert_eq!(missing_task_error, "task not found: task-missing");

        let no_media_error = analyze_task_with_state(task.task_id, &state)
            .expect_err("analysis without media should be rejected");
        assert_eq!(no_media_error, "task does not have a media file attached");
    }

    #[test]
    fn analyze_and_download_command_test_disambiguates_same_name_packet_payloads() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let first_payload = b"%PDF-1.7\nfirst command-level duplicate\n%%EOF\n";
        let second_payload = b"%PDF-1.7\nsecond command-level duplicate\n%%EOF\n";
        let first_packet = stegascope_packet("shared-command-note.pdf", first_payload);
        let second_packet = stegascope_packet("shared-command-note.pdf", second_payload);
        let carrier_bytes = png_with_text_chunks(&[
            (b"Comment".as_slice(), first_packet.as_slice()),
            (b"Comment".as_slice(), second_packet.as_slice()),
        ]);

        attach_media_file_with_state(
            task_id.clone(),
            UploadedMediaInput {
                file_name: "duplicate-packets.png".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: carrier_bytes,
            },
            &state,
        )
        .expect("media file should attach");

        let result = analyze_task_with_state(task_id.clone(), &state)
            .expect("duplicate packet analysis should run");
        let stored_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("stored duplicate packet metadata should be readable");
        let shared_files = stored_files
            .iter()
            .filter(|file| file.file_name == "shared-command-note.pdf")
            .collect::<Vec<_>>();

        assert_eq!(result.extracted_files.len(), 2);
        assert_eq!(result.extracted_files, stored_files);
        assert_eq!(shared_files.len(), 2);
        assert_ne!(shared_files[0].id, shared_files[1].id);
        assert!(shared_files
            .iter()
            .all(|file| file.analyzer_name == "metadata-analyzer"));
        assert!(shared_files
            .iter()
            .all(|file| file.validation_status == ValidationStatus::Verified));

        let temp_dir = TempDir::new("downloads-analyzed-same-name-payloads");
        let first_target = temp_dir.path().join("first.pdf");
        let second_target = temp_dir.path().join("second.pdf");

        download_extracted_file_with_state(
            task_id.clone(),
            shared_files[0].id.clone(),
            first_target
                .to_str()
                .expect("first target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("first analyzed same-name payload should download");
        download_extracted_file_with_state(
            task_id,
            shared_files[1].id.clone(),
            second_target
                .to_str()
                .expect("second target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("second analyzed same-name payload should download");

        let downloaded_payloads = [
            fs::read(&first_target).expect("first analyzed payload should be readable"),
            fs::read(&second_target).expect("second analyzed payload should be readable"),
        ];

        assert_ne!(downloaded_payloads[0], downloaded_payloads[1]);
        assert!(downloaded_payloads.contains(&first_payload.to_vec()));
        assert!(downloaded_payloads.contains(&second_payload.to_vec()));
    }

    #[test]
    fn analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_payloads() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let first_payload = b"%PDF-1.7\nfirst JPEG segment duplicate\n%%EOF\n";
        let second_payload = b"%PDF-1.7\nsecond JPEG segment duplicate\n%%EOF\n";
        let first_packet = stegascope_packet("shared-jpeg-note.pdf", first_payload);
        let second_packet = stegascope_packet("shared-jpeg-note.pdf", second_payload);
        let carrier_bytes = jpeg_with_segments(&[
            (0xFE, first_packet.as_slice()),
            (0xE1, second_packet.as_slice()),
        ]);

        attach_media_file_with_state(
            task_id.clone(),
            UploadedMediaInput {
                file_name: "duplicate-packets.jpg".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: carrier_bytes,
            },
            &state,
        )
        .expect("JPEG media file should attach");

        let result =
            analyze_task_with_state(task_id.clone(), &state).expect("JPEG analysis should run");
        let stored_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("stored JPEG packet metadata should be readable");
        let shared_files = stored_files
            .iter()
            .filter(|file| file.file_name == "shared-jpeg-note.pdf")
            .collect::<Vec<_>>();

        assert_eq!(result.extracted_files.len(), 2);
        assert_eq!(result.extracted_files, stored_files);
        assert_eq!(shared_files.len(), 2);
        assert_ne!(shared_files[0].id, shared_files[1].id);
        assert!(shared_files
            .iter()
            .all(|file| file.analyzer_name == "jpeg-segment-analyzer"));
        assert!(shared_files
            .iter()
            .all(|file| file.validation_status == ValidationStatus::Verified));

        let temp_dir = TempDir::new("downloads-analyzed-same-name-jpeg-payloads");
        let first_target = temp_dir.path().join("first.pdf");
        let second_target = temp_dir.path().join("second.pdf");

        download_extracted_file_with_state(
            task_id.clone(),
            shared_files[0].id.clone(),
            first_target
                .to_str()
                .expect("first target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("first analyzed same-name JPEG payload should download");
        download_extracted_file_with_state(
            task_id,
            shared_files[1].id.clone(),
            second_target
                .to_str()
                .expect("second target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("second analyzed same-name JPEG payload should download");

        let downloaded_payloads = [
            fs::read(&first_target).expect("first analyzed JPEG payload should be readable"),
            fs::read(&second_target).expect("second analyzed JPEG payload should be readable"),
        ];

        assert_ne!(downloaded_payloads[0], downloaded_payloads[1]);
        assert!(downloaded_payloads.contains(&first_payload.to_vec()));
        assert!(downloaded_payloads.contains(&second_payload.to_vec()));
    }

    #[test]
    fn analyze_and_download_command_test_disambiguates_same_name_jpeg_segment_after_eoi_payloads() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let segment_payload = b"%PDF-1.7\nJPEG segment duplicate\n%%EOF\n";
        let after_eoi_payload = b"%PDF-1.7\nJPEG after-EOI duplicate\n%%EOF\n";
        let segment_packet = stegascope_packet("shared-jpeg-note.pdf", segment_payload);
        let after_eoi_packet = stegascope_packet("shared-jpeg-note.pdf", after_eoi_payload);
        let mut carrier_bytes = jpeg_with_segments(&[(0xFE, segment_packet.as_slice())]);
        carrier_bytes.extend_from_slice(&after_eoi_packet);

        attach_media_file_with_state(
            task_id.clone(),
            UploadedMediaInput {
                file_name: "duplicate-segment-after-eoi-packets.jpg".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: carrier_bytes,
            },
            &state,
        )
        .expect("JPEG media file should attach");

        let result =
            analyze_task_with_state(task_id.clone(), &state).expect("JPEG analysis should run");
        let stored_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("stored JPEG packet metadata should be readable");
        let shared_files = stored_files
            .iter()
            .filter(|file| file.file_name == "shared-jpeg-note.pdf")
            .collect::<Vec<_>>();

        assert_eq!(result.extracted_files.len(), 2);
        assert_eq!(result.extracted_files, stored_files);
        assert_eq!(shared_files.len(), 2);
        assert_ne!(shared_files[0].id, shared_files[1].id);
        assert!(shared_files
            .iter()
            .all(|file| file.analyzer_name == "jpeg-segment-analyzer"));
        assert!(shared_files
            .iter()
            .all(|file| file.validation_status == ValidationStatus::Verified));

        let temp_dir = TempDir::new("downloads-analyzed-segment-after-eoi-jpeg-payloads");
        let first_target = temp_dir.path().join("first.pdf");
        let second_target = temp_dir.path().join("second.pdf");

        download_extracted_file_with_state(
            task_id.clone(),
            shared_files[0].id.clone(),
            first_target
                .to_str()
                .expect("first target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("same-name JPEG segment payload should download");
        download_extracted_file_with_state(
            task_id,
            shared_files[1].id.clone(),
            second_target
                .to_str()
                .expect("second target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("same-name JPEG after-EOI payload should download");

        let downloaded_payloads = [
            fs::read(&first_target).expect("first analyzed JPEG payload should be readable"),
            fs::read(&second_target).expect("second analyzed JPEG payload should be readable"),
        ];

        assert_ne!(downloaded_payloads[0], downloaded_payloads[1]);
        assert!(downloaded_payloads.contains(&segment_payload.to_vec()));
        assert!(downloaded_payloads.contains(&after_eoi_payload.to_vec()));
    }

    #[test]
    fn analyze_and_download_command_test_rejects_payload_id_after_reattach() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let task_id = task.task_id;
        let first_payload = b"%PDF-1.7\nfirst reattached payload\n%%EOF\n";
        let second_payload = b"%PDF-1.7\nsecond reattached payload\n%%EOF\n";
        let first_packet = stegascope_packet("reattached-note.pdf", first_payload);
        let second_packet = stegascope_packet("reattached-note.pdf", second_payload);

        attach_media_file_with_state(
            task_id.clone(),
            UploadedMediaInput {
                file_name: "first-carrier.png".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: png_with_text_chunks(&[(b"Comment".as_slice(), first_packet.as_slice())]),
            },
            &state,
        )
        .expect("first media file should attach");
        analyze_task_with_state(task_id.clone(), &state).expect("first analysis should run");
        let stale_file_id = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("first analysis result should be readable")
            .first()
            .expect("first analysis should expose a payload")
            .id
            .clone();

        attach_media_file_with_state(
            task_id.clone(),
            UploadedMediaInput {
                file_name: "second-carrier.png".to_string(),
                file_size_bytes: 0,
                file_type: String::new(),
                bytes: png_with_text_chunks(&[(b"Comment".as_slice(), second_packet.as_slice())]),
            },
            &state,
        )
        .expect("second media file should attach");
        assert!(get_extracted_files_with_state(task_id.clone(), &state)
            .expect("reattach should leave result metadata readable")
            .is_empty());

        analyze_task_with_state(task_id.clone(), &state).expect("second analysis should run");
        let current_files = get_extracted_files_with_state(task_id.clone(), &state)
            .expect("second analysis result should be readable");
        assert_eq!(current_files.len(), 1);
        assert_ne!(stale_file_id, current_files[0].id);

        let temp_dir = TempDir::new("rejects-reattached-stale-payload-id");
        let stale_target = temp_dir.path().join("stale.pdf");
        let error = download_extracted_file_with_state(
            task_id.clone(),
            stale_file_id.clone(),
            stale_target
                .to_str()
                .expect("stale target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("stale payload id should be rejected after reattach");
        assert_eq!(
            error,
            format!("extracted file bytes not found in current analysis result: {stale_file_id}")
        );
        assert!(!stale_target.exists());

        let current_target = temp_dir.path().join("current.pdf");
        download_extracted_file_with_state(
            task_id,
            current_files[0].id.clone(),
            current_target
                .to_str()
                .expect("current target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("current payload should download after reattach");

        assert_eq!(
            fs::read(&current_target).expect("current payload should be readable"),
            second_payload.to_vec()
        );
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

        assert_eq!(stored_files.len(), 1);
        assert_eq!(stored_files[0].file_name, extracted_file.file_name);
        assert_eq!(stored_files[0].analyzer_name, extracted_file.analyzer_name);
        assert_eq!(stored_files[0].file_type, extracted_file.file_type);
        assert!(stored_files[0].id.starts_with("payload-"));
    }

    #[test]
    fn get_extracted_files_command_test_rejects_blank_or_missing_task() {
        let state = AppState::default();

        let blank_task_id_error = get_extracted_files_with_state("   ".to_string(), &state)
            .expect_err("blank task id should be rejected");
        assert_eq!(blank_task_id_error, "task id is required");

        let missing_task_error = get_extracted_files_with_state("task-missing".to_string(), &state)
            .expect_err("missing task should be rejected");
        assert_eq!(missing_task_error, "task not found: task-missing");
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

        let stored_files = get_extracted_files_with_state(task.task_id.clone(), &state)
            .expect("stored extracted files should be readable");
        let file_id = stored_files
            .first()
            .expect("stored payload should expose an id")
            .id
            .clone();

        let temp_dir = TempDir::new("downloads-current-payload");
        let target_path = temp_dir.path().join("exports").join("downloaded-note.pdf");
        let response = download_extracted_file_with_state(
            task.task_id,
            format!(" {file_id} "),
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
    fn download_extracted_file_command_test_rejects_stale_payload_id_after_result_replacement() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let extracted_file = sample_extracted_file("rotating-note.pdf", "unit-test-analyzer");

        {
            let mut tasks = lock_tasks(&state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(&task.task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![ExtractedPayload {
                file: extracted_file.clone(),
                bytes: b"previous analysis payload".to_vec(),
                source: PayloadSource::VerifiedPacket,
            }]);
        }

        let stale_file_id = get_extracted_files_with_state(task.task_id.clone(), &state)
            .expect("previous extracted file should be readable")
            .first()
            .expect("previous payload should expose an id")
            .id
            .clone();

        {
            let mut tasks = lock_tasks(&state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(&task.task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![ExtractedPayload {
                file: extracted_file,
                bytes: b"current analysis payload".to_vec(),
                source: PayloadSource::VerifiedPacket,
            }]);
        }

        let current_file_id = get_extracted_files_with_state(task.task_id.clone(), &state)
            .expect("current extracted file should be readable")
            .first()
            .expect("current payload should expose an id")
            .id
            .clone();
        assert_ne!(stale_file_id, current_file_id);

        let temp_dir = TempDir::new("rejects-stale-payload-id");
        let target_path = temp_dir.path().join("stale.pdf");
        let error = download_extracted_file_with_state(
            task.task_id,
            stale_file_id.clone(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("stale payload id should be rejected");

        assert_eq!(
            error,
            format!("extracted file bytes not found in current analysis result: {stale_file_id}")
        );
        assert!(!target_path.exists());
    }

    #[test]
    fn download_extracted_file_command_test_uses_file_id_for_same_name_payloads() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let extracted_file = sample_extracted_file("shared-note.pdf", "unit-test-analyzer");

        {
            let mut tasks = lock_tasks(&state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(&task.task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![
                ExtractedPayload {
                    file: extracted_file.clone(),
                    bytes: b"first shared-name payload".to_vec(),
                    source: PayloadSource::VerifiedPacket,
                },
                ExtractedPayload {
                    file: extracted_file,
                    bytes: b"second shared-name payload".to_vec(),
                    source: PayloadSource::VerifiedPacket,
                },
            ]);
        }

        let stored_files = get_extracted_files_with_state(task.task_id.clone(), &state)
            .expect("stored extracted files should be readable");

        assert_eq!(stored_files.len(), 2);
        assert_eq!(stored_files[0].file_name, "shared-note.pdf");
        assert_eq!(stored_files[1].file_name, "shared-note.pdf");
        assert_ne!(stored_files[0].id, stored_files[1].id);

        let temp_dir = TempDir::new("downloads-same-name-payloads");
        let first_target = temp_dir.path().join("first.pdf");
        let second_target = temp_dir.path().join("second.pdf");

        download_extracted_file_with_state(
            task.task_id.clone(),
            stored_files[0].id.clone(),
            first_target
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("first same-name payload should download");
        download_extracted_file_with_state(
            task.task_id,
            stored_files[1].id.clone(),
            second_target
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("second same-name payload should download");

        assert_eq!(
            fs::read(&first_target).expect("first payload should be readable"),
            b"first shared-name payload"
        );
        assert_eq!(
            fs::read(&second_target).expect("second payload should be readable"),
            b"second shared-name payload"
        );
    }

    #[test]
    fn download_extracted_file_command_test_uses_file_id_for_same_name_signature_scan_payloads() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let extracted_file =
            sample_extracted_file("shared-signature-note.pdf", "unit-test-analyzer");

        {
            let mut tasks = lock_tasks(&state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(&task.task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![
                ExtractedPayload {
                    file: extracted_file.clone(),
                    bytes: b"first shared-name signature payload".to_vec(),
                    source: PayloadSource::SignatureScan,
                },
                ExtractedPayload {
                    file: extracted_file,
                    bytes: b"second shared-name signature payload".to_vec(),
                    source: PayloadSource::SignatureScan,
                },
            ]);
        }

        let stored_files = get_extracted_files_with_state(task.task_id.clone(), &state)
            .expect("stored extracted files should be readable");

        assert_eq!(stored_files.len(), 2);
        assert_eq!(stored_files[0].file_name, "shared-signature-note.pdf");
        assert_eq!(stored_files[1].file_name, "shared-signature-note.pdf");
        assert_ne!(stored_files[0].id, stored_files[1].id);

        let temp_dir = TempDir::new("downloads-same-name-signature-payloads");
        let first_target = temp_dir.path().join("first.bin");
        let second_target = temp_dir.path().join("second.bin");

        download_extracted_file_with_state(
            task.task_id.clone(),
            stored_files[0].id.clone(),
            first_target
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("first same-name signature payload should download");
        download_extracted_file_with_state(
            task.task_id,
            stored_files[1].id.clone(),
            second_target
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect("second same-name signature payload should download");

        assert_eq!(
            fs::read(&first_target).expect("first payload should be readable"),
            b"first shared-name signature payload"
        );
        assert_eq!(
            fs::read(&second_target).expect("second payload should be readable"),
            b"second shared-name signature payload"
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
            "missing-payload-id".to_string(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("missing payload should be rejected");

        assert_eq!(
            error,
            "extracted file bytes not found in current analysis result: missing-payload-id"
        );
        assert!(!target_path.exists());
    }

    #[test]
    fn download_extracted_file_command_test_rejects_blank_payload_id() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let temp_dir = TempDir::new("rejects-blank-payload-id");
        let target_path = temp_dir.path().join("blank.bin");

        let error = download_extracted_file_with_state(
            task.task_id,
            "   ".to_string(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("blank payload id should be rejected");

        assert_eq!(error, "file id is required");
        assert!(!target_path.exists());
    }

    #[test]
    fn download_extracted_file_command_test_rejects_blank_task_id() {
        let state = AppState::default();
        let temp_dir = TempDir::new("rejects-blank-download-task-id");
        let target_path = temp_dir.path().join("blank-task.bin");

        let error = download_extracted_file_with_state(
            "   ".to_string(),
            "payload-id".to_string(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("blank download task id should be rejected");

        assert_eq!(error, "task id is required");
        assert!(!target_path.exists());
    }

    #[test]
    fn download_extracted_file_command_test_rejects_missing_task_without_writing() {
        let state = AppState::default();
        let temp_dir = TempDir::new("rejects-missing-download-task");
        let target_path = temp_dir.path().join("missing-task.bin");

        let error = download_extracted_file_with_state(
            "task-missing".to_string(),
            "payload-id".to_string(),
            target_path
                .to_str()
                .expect("target path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("missing download task should be rejected");

        assert_eq!(error, "task not found: task-missing");
        assert!(!target_path.exists());
    }

    #[test]
    fn download_extracted_file_command_test_rejects_blank_save_path() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let file_id = store_sample_payload(
            &state,
            &task.task_id,
            "blank-save-path-note.pdf",
            b"blank save path payload",
        );

        let error =
            download_extracted_file_with_state(task.task_id, file_id, "   ".to_string(), &state)
                .expect_err("blank save path should be rejected");

        assert_eq!(error, "save path is required");
    }

    #[test]
    fn download_extracted_file_command_test_rejects_directory_save_path_without_writing() {
        let state = AppState::default();
        let task =
            create_task_with_state(sample_task_input(), &state).expect("task should be created");
        let file_id = store_sample_payload(
            &state,
            &task.task_id,
            "directory-target-note.pdf",
            b"directory target payload",
        );
        let temp_dir = TempDir::new("rejects-directory-download-target");
        let directory_path = temp_dir.path().join("existing-directory");
        fs::create_dir_all(&directory_path).expect("directory target should be created");

        let error = download_extracted_file_with_state(
            task.task_id,
            file_id,
            directory_path
                .to_str()
                .expect("directory path should be utf-8")
                .to_string(),
            &state,
        )
        .expect_err("directory save path should be rejected");

        assert_eq!(error, "save path points to a directory");
        assert!(fs::read_dir(&directory_path)
            .expect("directory should still be readable")
            .next()
            .is_none());
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

    fn png_with_text_chunks(chunks: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = png_image_bytes();
        let mut inserted_chunks = Vec::new();

        for (keyword, payload) in chunks {
            let mut chunk_data = Vec::new();
            chunk_data.extend_from_slice(keyword);
            chunk_data.push(0);
            chunk_data.extend_from_slice(payload);
            inserted_chunks.extend_from_slice(&png_chunk(*b"tEXt", &chunk_data));
        }

        let iend_type_offset = bytes
            .windows(4)
            .position(|window| window == b"IEND")
            .expect("encoded PNG should contain IEND chunk");
        let iend_chunk_offset = iend_type_offset - 4;
        bytes.splice(iend_chunk_offset..iend_chunk_offset, inserted_chunks);

        bytes
    }

    fn png_with_after_iend_payload(payload: &[u8]) -> Vec<u8> {
        let mut bytes = png_image_bytes();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn jpeg_image_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        let pixels = [0_u8, 0, 0];
        image::codecs::jpeg::JpegEncoder::new(&mut bytes)
            .write_image(&pixels, 1, 1, image::ExtendedColorType::Rgb8)
            .expect("test JPEG should encode");
        bytes
    }

    fn jpeg_image_with_comment_segment(payload: &[u8]) -> Vec<u8> {
        let mut bytes = jpeg_image_bytes();
        let comment_segment = jpeg_segment_bytes(0xFE, payload);

        assert!(bytes.starts_with(b"\xFF\xD8"));
        bytes.splice(2..2, comment_segment);

        bytes
    }

    fn jpeg_image_with_after_eoi_payload(payload: &[u8]) -> Vec<u8> {
        let mut bytes = jpeg_image_bytes();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn png_chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend_from_slice(&kind);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&png_crc32(&kind, data).to_be_bytes());
        chunk
    }

    fn png_crc32(kind: &[u8; 4], data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF_u32;

        for byte in kind.iter().chain(data.iter()) {
            crc ^= *byte as u32;
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }

        !crc
    }

    fn stegascope_packet(file_name: &str, payload: &[u8]) -> Vec<u8> {
        const STEGASCOPE_PACKET_MAGIC: &[u8; 8] = b"SS2X3ME1";

        let name_bytes = file_name.as_bytes();
        let mut packet = Vec::new();
        packet.extend_from_slice(STEGASCOPE_PACKET_MAGIC);
        packet.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        packet.extend_from_slice(&Sha256::digest(payload));
        packet.extend_from_slice(name_bytes);
        packet.extend_from_slice(payload);
        packet
    }

    fn jpeg_with_segments(segments: &[(u8, &[u8])]) -> Vec<u8> {
        const JPEG_SOI: &[u8; 2] = b"\xFF\xD8";
        const JPEG_EOI: &[u8; 2] = b"\xFF\xD9";

        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        for (marker, payload) in segments {
            bytes.extend_from_slice(&jpeg_segment_bytes(*marker, payload));
        }
        bytes.extend_from_slice(JPEG_EOI);
        bytes
    }

    fn jpeg_segment_bytes(marker: u8, data: &[u8]) -> Vec<u8> {
        let segment_length = data
            .len()
            .checked_add(2)
            .expect("test JPEG segment should fit length field");
        assert!(segment_length <= u16::MAX as usize);

        let mut segment = Vec::new();
        segment.push(0xFF);
        segment.push(marker);
        segment.extend_from_slice(&(segment_length as u16).to_be_bytes());
        segment.extend_from_slice(data);
        segment
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

    fn store_sample_payload(
        state: &AppState,
        task_id: &str,
        file_name: &str,
        bytes: &[u8],
    ) -> String {
        let extracted_file = sample_extracted_file(file_name, "unit-test-analyzer");

        {
            let mut tasks = lock_tasks(state).expect("task store should lock");
            let stored_task = tasks
                .get_mut(task_id)
                .expect("created task should be present");
            stored_task.replace_extracted_payloads(vec![ExtractedPayload {
                file: extracted_file,
                bytes: bytes.to_vec(),
                source: PayloadSource::SignatureScan,
            }]);
        }

        get_extracted_files_with_state(task_id.to_string(), state)
            .expect("stored extracted files should be readable")
            .first()
            .expect("stored payload should expose an id")
            .id
            .clone()
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
            fs::create_dir_all(&path).expect("temporary test directory should be created");

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
