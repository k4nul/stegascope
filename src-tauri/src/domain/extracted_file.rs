use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SuspiciousLevel {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ValidationStatus {
    Verified,
    Validated,
    Candidate,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileSignature {
    pub is_known: bool,
    pub label: String,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
    pub header_hex: String,
}

impl FileSignature {
    pub fn known(
        label: impl Into<String>,
        extension: impl Into<String>,
        mime_type: impl Into<String>,
        header_hex: impl Into<String>,
    ) -> Self {
        Self {
            is_known: true,
            label: label.into(),
            extension: Some(extension.into()),
            mime_type: Some(mime_type.into()),
            header_hex: header_hex.into(),
        }
    }

    pub fn unknown(header_hex: impl Into<String>) -> Self {
        Self {
            is_known: false,
            label: "Unknown file signature".to_string(),
            extension: None,
            mime_type: None,
            header_hex: header_hex.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedFile {
    pub file_name: String,
    pub analyzer_name: String,
    pub suspicious_level: SuspiciousLevel,
    pub validation_status: ValidationStatus,
    pub validation_note: String,
    pub file_size_bytes: u64,
    pub file_type: String,
    pub file_signature: FileSignature,
}

impl ExtractedFile {
    pub fn new(
        file_name: impl Into<String>,
        analyzer_name: impl Into<String>,
        suspicious_level: SuspiciousLevel,
        validation_status: ValidationStatus,
        validation_note: impl Into<String>,
        file_size_bytes: u64,
        file_type: impl Into<String>,
        file_signature: FileSignature,
    ) -> Self {
        Self {
            file_name: file_name.into(),
            analyzer_name: analyzer_name.into(),
            suspicious_level,
            validation_status,
            validation_note: validation_note.into(),
            file_size_bytes,
            file_type: file_type.into(),
            file_signature,
        }
    }
}
