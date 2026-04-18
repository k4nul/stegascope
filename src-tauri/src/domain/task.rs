use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::domain::{ExtractedFile, FileAnalyzer, FileLoader, LoaderError};

#[derive(Debug)]
pub struct Task {
    pub case_number: String,
    pub case_name: String,
    pub date: String,
    pub investigator_name: String,
    loader: Option<Box<dyn FileLoader>>,
    extracted_files: Vec<ExtractedFile>,
}

impl Task {
    pub fn new(
        case_number: impl Into<String>,
        case_name: impl Into<String>,
        date: impl Into<String>,
        investigator_name: impl Into<String>,
    ) -> Self {
        Self {
            case_number: case_number.into(),
            case_name: case_name.into(),
            date: date.into(),
            investigator_name: investigator_name.into(),
            loader: None,
            extracted_files: Vec::new(),
        }
    }

    pub fn set_loader(&mut self, loader: Box<dyn FileLoader>) {
        self.loader = Some(loader);
    }

    pub fn loader(&self) -> Option<&dyn FileLoader> {
        self.loader.as_deref()
    }

    pub fn extracted_files(&self) -> &[ExtractedFile] {
        &self.extracted_files
    }

    pub fn collect_extracted_files(
        &mut self,
        files: impl IntoIterator<Item = ExtractedFile>,
    ) -> &[ExtractedFile] {
        self.extracted_files.extend(files);
        &self.extracted_files
    }

    pub fn run_analyzers(
        &mut self,
        analyzers: &[Box<dyn FileAnalyzer>],
    ) -> Result<&[ExtractedFile], TaskError> {
        let loader = self.loader.as_ref().ok_or(TaskError::MissingLoader)?;
        let outcomes = loader
            .invoke_analyzers(analyzers)
            .map_err(TaskError::Loader)?;

        for outcome in outcomes {
            self.collect_extracted_files(outcome.extracted_files);
        }

        Ok(self.extracted_files())
    }
}

#[derive(Debug)]
pub enum TaskError {
    MissingLoader,
    Loader(LoaderError),
}

impl Display for TaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLoader => write!(f, "task does not have a file loader attached"),
            Self::Loader(error) => write!(f, "{error}"),
        }
    }
}

impl Error for TaskError {}
