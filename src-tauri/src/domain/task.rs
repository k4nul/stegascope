use crate::domain::{ExtractedFile, ExtractedPayload, FileLoader};

#[derive(Debug)]
pub struct Task {
    pub case_number: String,
    pub case_name: String,
    pub date: String,
    pub investigator_name: String,
    loader: Option<Box<dyn FileLoader>>,
    extracted_files: Vec<ExtractedFile>,
    extracted_payloads: Vec<ExtractedPayload>,
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
            extracted_payloads: Vec::new(),
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

    pub fn extracted_payloads(&self) -> &[ExtractedPayload] {
        &self.extracted_payloads
    }

    pub fn collect_extracted_files(
        &mut self,
        files: impl IntoIterator<Item = ExtractedFile>,
    ) -> &[ExtractedFile] {
        self.extracted_files.extend(files);
        &self.extracted_files
    }

    pub fn clear_extracted_files(&mut self) {
        self.extracted_files.clear();
        self.extracted_payloads.clear();
    }

    pub fn replace_extracted_payloads(
        &mut self,
        payloads: Vec<ExtractedPayload>,
    ) -> &[ExtractedFile] {
        self.extracted_files = payloads
            .iter()
            .map(|payload| payload.file.clone())
            .collect();
        self.extracted_payloads = payloads;
        &self.extracted_files
    }
}
