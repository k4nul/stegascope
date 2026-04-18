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
pub struct ExtractedFile {
    pub file_name: String,
    pub suspicious_level: SuspiciousLevel,
    pub file_size_bytes: u64,
    pub file_type: String,
}

impl ExtractedFile {
    pub fn new(
        file_name: impl Into<String>,
        suspicious_level: SuspiciousLevel,
        file_size_bytes: u64,
        file_type: impl Into<String>,
    ) -> Self {
        Self {
            file_name: file_name.into(),
            suspicious_level,
            file_size_bytes,
            file_type: file_type.into(),
        }
    }
}
