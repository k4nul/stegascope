pub mod analyzer;
pub mod extracted_file;
pub mod file_loader;
pub mod media_file;
pub mod task;

pub use analyzer::{AnalysisError, AnalysisOutcome, BaseFileAnalyzer, FileAnalyzer, LoadedMedia};
pub use extracted_file::{ExtractedFile, SuspiciousLevel};
pub use file_loader::{
    AudioLoader, BaseFileLoader, FileLoader, ImageLoader, LoaderError, VideoLoader,
};
pub use media_file::MediaFileInfo;
pub use task::{Task, TaskError};
