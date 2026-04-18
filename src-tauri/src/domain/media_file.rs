use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MediaFileInfo {
    pub file_name: String,
    pub file_size_bytes: u64,
    pub file_type: String,
}

impl MediaFileInfo {
    pub fn new(
        file_name: impl Into<String>,
        file_size_bytes: u64,
        file_type: impl Into<String>,
    ) -> Self {
        Self {
            file_name: file_name.into(),
            file_size_bytes,
            file_type: file_type.into(),
        }
    }
}
