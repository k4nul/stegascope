use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::domain::{ExtractedFile, MediaFileInfo};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BaseFileAnalyzer {
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
}

impl BaseFileAnalyzer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            description: None,
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoadedMedia {
    pub source: MediaFileInfo,
    pub bytes: Vec<u8>,
}

impl LoadedMedia {
    pub fn empty(source: MediaFileInfo) -> Self {
        Self {
            source,
            bytes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisOutcome {
    pub extracted_files: Vec<ExtractedFile>,
}

impl AnalysisOutcome {
    pub fn new(extracted_files: Vec<ExtractedFile>) -> Self {
        Self { extracted_files }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnalysisError {
    UnsupportedFormat,
    ExtractionFailed(String),
}

impl Display for AnalysisError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => write!(f, "analyzer does not support this media format"),
            Self::ExtractionFailed(message) => write!(f, "analysis failed: {message}"),
        }
    }
}

impl Error for AnalysisError {}

pub trait FileAnalyzer: std::fmt::Debug + Send + Sync {
    fn base(&self) -> &BaseFileAnalyzer;

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError>;

    fn name(&self) -> &str {
        &self.base().name
    }
}
