use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::domain::{AnalysisError, AnalysisOutcome, FileAnalyzer, LoadedMedia, MediaFileInfo};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BaseFileLoader {
    pub file_name: String,
    pub media_info: MediaFileInfo,
}

impl BaseFileLoader {
    pub fn new(file_name: impl Into<String>, media_info: MediaFileInfo) -> Self {
        Self {
            file_name: file_name.into(),
            media_info,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LoaderError {
    InvalidPath(String),
    UnsupportedMediaType(String),
    ReadFailed(String),
    AnalyzerFailure(String),
}

impl Display for LoaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(f, "invalid file path: {path}"),
            Self::UnsupportedMediaType(file_type) => {
                write!(f, "unsupported media type for loader: {file_type}")
            }
            Self::ReadFailed(message) => write!(f, "failed to read file: {message}"),
            Self::AnalyzerFailure(message) => write!(f, "analyzer invocation failed: {message}"),
        }
    }
}

impl Error for LoaderError {}

impl From<AnalysisError> for LoaderError {
    fn from(value: AnalysisError) -> Self {
        Self::AnalyzerFailure(value.to_string())
    }
}

pub trait FileLoader: std::fmt::Debug + Send + Sync {
    fn base(&self) -> &BaseFileLoader;

    fn load(&self) -> Result<LoadedMedia, LoaderError>;

    fn file_name(&self) -> &str {
        &self.base().file_name
    }

    fn media_info(&self) -> &MediaFileInfo {
        &self.base().media_info
    }

    fn invoke_analyzer(&self, analyzer: &dyn FileAnalyzer) -> Result<AnalysisOutcome, LoaderError> {
        let media = self.load()?;
        analyzer.analyze(&media).map_err(LoaderError::from)
    }

    fn invoke_analyzers(
        &self,
        analyzers: &[Box<dyn FileAnalyzer>],
    ) -> Result<Vec<AnalysisOutcome>, LoaderError> {
        let media = self.load()?;

        analyzers
            .iter()
            .map(|analyzer| analyzer.analyze(&media).map_err(LoaderError::from))
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageLoader {
    pub base: BaseFileLoader,
}

impl ImageLoader {
    pub fn new(media_info: MediaFileInfo) -> Self {
        let file_name = media_info.file_name.clone();
        Self {
            base: BaseFileLoader::new(file_name, media_info),
        }
    }
}

impl FileLoader for ImageLoader {
    fn base(&self) -> &BaseFileLoader {
        &self.base
    }

    fn load(&self) -> Result<LoadedMedia, LoaderError> {
        Ok(LoadedMedia::empty(self.base.media_info.clone()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VideoLoader {
    pub base: BaseFileLoader,
}

impl VideoLoader {
    pub fn new(media_info: MediaFileInfo) -> Self {
        let file_name = media_info.file_name.clone();
        Self {
            base: BaseFileLoader::new(file_name, media_info),
        }
    }
}

impl FileLoader for VideoLoader {
    fn base(&self) -> &BaseFileLoader {
        &self.base
    }

    fn load(&self) -> Result<LoadedMedia, LoaderError> {
        Ok(LoadedMedia::empty(self.base.media_info.clone()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AudioLoader {
    pub base: BaseFileLoader,
}

impl AudioLoader {
    pub fn new(media_info: MediaFileInfo) -> Self {
        let file_name = media_info.file_name.clone();
        Self {
            base: BaseFileLoader::new(file_name, media_info),
        }
    }
}

impl FileLoader for AudioLoader {
    fn base(&self) -> &BaseFileLoader {
        &self.base
    }

    fn load(&self) -> Result<LoadedMedia, LoaderError> {
        Ok(LoadedMedia::empty(self.base.media_info.clone()))
    }
}
