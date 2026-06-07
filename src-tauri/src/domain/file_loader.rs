use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::domain::{LoadedMedia, MediaFileInfo};

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
}

impl Display for LoaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(f, "invalid file path: {path}"),
            Self::UnsupportedMediaType(file_type) => {
                write!(f, "unsupported media type for loader: {file_type}")
            }
            Self::ReadFailed(message) => write!(f, "failed to read file: {message}"),
        }
    }
}

impl Error for LoaderError {}

pub trait FileLoader: std::fmt::Debug + Send + Sync {
    fn base(&self) -> &BaseFileLoader;

    fn load(&self) -> Result<LoadedMedia, LoaderError>;

    fn file_name(&self) -> &str {
        &self.base().file_name
    }

    fn media_info(&self) -> &MediaFileInfo {
        &self.base().media_info
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageLoader {
    pub base: BaseFileLoader,
    pub bytes: Vec<u8>,
}

impl ImageLoader {
    pub fn new(media_info: MediaFileInfo, bytes: Vec<u8>) -> Self {
        let file_name = media_info.file_name.clone();
        Self {
            base: BaseFileLoader::new(file_name, media_info),
            bytes,
        }
    }
}

impl FileLoader for ImageLoader {
    fn base(&self) -> &BaseFileLoader {
        &self.base
    }

    fn load(&self) -> Result<LoadedMedia, LoaderError> {
        Ok(LoadedMedia {
            source: self.base.media_info.clone(),
            bytes: self.bytes.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VideoLoader {
    pub base: BaseFileLoader,
    pub bytes: Vec<u8>,
}

impl VideoLoader {
    pub fn new(media_info: MediaFileInfo, bytes: Vec<u8>) -> Self {
        let file_name = media_info.file_name.clone();
        Self {
            base: BaseFileLoader::new(file_name, media_info),
            bytes,
        }
    }
}

impl FileLoader for VideoLoader {
    fn base(&self) -> &BaseFileLoader {
        &self.base
    }

    fn load(&self) -> Result<LoadedMedia, LoaderError> {
        Ok(LoadedMedia {
            source: self.base.media_info.clone(),
            bytes: self.bytes.clone(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AudioLoader {
    pub base: BaseFileLoader,
    pub bytes: Vec<u8>,
}

impl AudioLoader {
    pub fn new(media_info: MediaFileInfo, bytes: Vec<u8>) -> Self {
        let file_name = media_info.file_name.clone();
        Self {
            base: BaseFileLoader::new(file_name, media_info),
            bytes,
        }
    }
}

impl FileLoader for AudioLoader {
    fn base(&self) -> &BaseFileLoader {
        &self.base
    }

    fn load(&self) -> Result<LoadedMedia, LoaderError> {
        Ok(LoadedMedia {
            source: self.base.media_info.clone(),
            bytes: self.bytes.clone(),
        })
    }
}

pub trait FileLoaderFactory: std::fmt::Debug + Send + Sync {
    fn supports(&self, media_info: &MediaFileInfo) -> bool;

    fn create(&self, media_info: MediaFileInfo, bytes: Vec<u8>) -> Box<dyn FileLoader>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ImageLoaderFactory;

impl FileLoaderFactory for ImageLoaderFactory {
    fn supports(&self, media_info: &MediaFileInfo) -> bool {
        media_info
            .file_type
            .to_ascii_lowercase()
            .starts_with("image/")
    }

    fn create(&self, media_info: MediaFileInfo, bytes: Vec<u8>) -> Box<dyn FileLoader> {
        Box::new(ImageLoader::new(media_info, bytes))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AudioLoaderFactory;

impl FileLoaderFactory for AudioLoaderFactory {
    fn supports(&self, media_info: &MediaFileInfo) -> bool {
        media_info
            .file_type
            .to_ascii_lowercase()
            .starts_with("audio/")
    }

    fn create(&self, media_info: MediaFileInfo, bytes: Vec<u8>) -> Box<dyn FileLoader> {
        Box::new(AudioLoader::new(media_info, bytes))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VideoLoaderFactory;

impl FileLoaderFactory for VideoLoaderFactory {
    fn supports(&self, media_info: &MediaFileInfo) -> bool {
        media_info
            .file_type
            .to_ascii_lowercase()
            .starts_with("video/")
    }

    fn create(&self, media_info: MediaFileInfo, bytes: Vec<u8>) -> Box<dyn FileLoader> {
        Box::new(VideoLoader::new(media_info, bytes))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MediaLoaderFactory;

impl MediaLoaderFactory {
    pub fn create(
        &self,
        media_info: MediaFileInfo,
        bytes: Vec<u8>,
    ) -> Result<Box<dyn FileLoader>, LoaderError> {
        let file_type = media_info.file_type.to_ascii_lowercase();
        let factories: [&dyn FileLoaderFactory; 3] = [
            &ImageLoaderFactory,
            &AudioLoaderFactory,
            &VideoLoaderFactory,
        ];

        for factory in factories {
            if factory.supports(&media_info) {
                return Ok(factory.create(media_info, bytes));
            }
        }

        Err(LoaderError::UnsupportedMediaType(file_type))
    }
}

pub fn create_loader(
    media_info: MediaFileInfo,
    bytes: Vec<u8>,
) -> Result<Box<dyn FileLoader>, LoaderError> {
    MediaLoaderFactory.create(media_info, bytes)
}
