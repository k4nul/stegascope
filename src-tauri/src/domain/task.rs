use crate::domain::analyzer_pipeline::finalize_extracted_payloads;
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
        let payloads = finalize_extracted_payloads(payloads);
        self.extracted_files = payloads
            .iter()
            .map(|payload| payload.file.clone())
            .collect();
        self.extracted_payloads = payloads;
        &self.extracted_files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FileSignature, PayloadSource, SuspiciousLevel, ValidationStatus};

    #[test]
    fn replace_extracted_payloads_dedupes_exact_payloads_before_assigning_ids() {
        let mut task = Task::new("CASE-001", "Synthetic case", "2026-06-17", "Automation");
        let first = test_payload(b"%PDF-1.7\nfirst\n%%EOF\n");
        let exact_duplicate = first.clone();
        let distinct_same_name = test_payload(b"%PDF-1.7\nsecond\n%%EOF\n");

        let files =
            task.replace_extracted_payloads(vec![first, exact_duplicate, distinct_same_name]);

        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|file| file.id.starts_with("payload-")));
        assert_ne!(files[0].id, files[1].id);
        assert_eq!(task.extracted_payloads().len(), 2);
    }

    #[test]
    fn replace_extracted_payloads_prefers_verified_payloads_before_assigning_ids() {
        let mut task = Task::new("CASE-001", "Synthetic case", "2026-06-17", "Automation");
        let signature_scan = test_payload_with_source(
            b"%PDF-1.7\nsignature fallback\n%%EOF\n",
            PayloadSource::SignatureScan,
        );
        let verified = test_payload_with_source(
            b"%PDF-1.7\nverified payload\n%%EOF\n",
            PayloadSource::VerifiedPacket,
        );

        let files = task.replace_extracted_payloads(vec![signature_scan, verified]);

        assert_eq!(files.len(), 1);
        assert!(files[0].id.starts_with("payload-"));
        assert_eq!(task.extracted_payloads().len(), 1);
        assert_eq!(
            task.extracted_payloads()[0].source,
            PayloadSource::VerifiedPacket
        );
        assert_eq!(
            task.extracted_payloads()[0].bytes,
            b"%PDF-1.7\nverified payload\n%%EOF\n"
        );
    }

    fn test_payload(bytes: &[u8]) -> ExtractedPayload {
        test_payload_with_source(bytes, PayloadSource::VerifiedPacket)
    }

    fn test_payload_with_source(bytes: &[u8], source: PayloadSource) -> ExtractedPayload {
        ExtractedPayload {
            file: ExtractedFile::new(
                "shared-note.pdf",
                "unit-test-analyzer",
                SuspiciousLevel::High,
                ValidationStatus::Validated,
                "test payload",
                bytes.len() as u64,
                "application/pdf",
                FileSignature::known("PDF document", "pdf", "application/pdf", "25 50 44 46"),
            ),
            bytes: bytes.to_vec(),
            source,
        }
    }
}
