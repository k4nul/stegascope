use super::analyzer::{
    AnalysisError, AnalysisOutcome, EmbeddedSignatureAnalyzer, ExtractedPayload, FileAnalyzer,
    JpegSegmentAnalyzer, LoadedMedia, Lsb2bppAnalyzer, LsbAnalyzer, MetadataAnalyzer,
    PayloadSource, PngContainerAnalyzer, WavPcmLsbAnalyzer,
};
use sha2::{Digest, Sha256};

pub fn default_analyzers() -> Vec<Box<dyn FileAnalyzer>> {
    vec![
        Box::<MetadataAnalyzer>::default(),
        Box::<PngContainerAnalyzer>::default(),
        Box::<JpegSegmentAnalyzer>::default(),
        Box::<EmbeddedSignatureAnalyzer>::default(),
        Box::<LsbAnalyzer>::default(),
        Box::<Lsb2bppAnalyzer>::default(),
        Box::<WavPcmLsbAnalyzer>::default(),
    ]
}

pub fn extract_payload_candidates(
    media: &LoadedMedia,
) -> Result<Vec<ExtractedPayload>, AnalysisError> {
    let mut payloads = Vec::new();

    for analyzer in default_analyzers() {
        let outcome = analyzer.analyze(media)?;
        payloads.extend(outcome.extracted_payloads);
    }

    Ok(finalize_extracted_payloads(payloads))
}

pub fn finalize_extracted_payloads(mut payloads: Vec<ExtractedPayload>) -> Vec<ExtractedPayload> {
    dedupe_payloads(&mut payloads);

    if payloads
        .iter()
        .any(|payload| payload.source == PayloadSource::VerifiedPacket)
    {
        payloads.retain(|payload| payload.source == PayloadSource::VerifiedPacket);
        dedupe_payloads(&mut payloads);
    }

    assign_payload_ids(&mut payloads);

    payloads
}

pub(crate) fn assign_payload_ids(payloads: &mut [ExtractedPayload]) {
    for payload in payloads {
        payload.file.id = payload_identifier(payload);
    }
}

pub(super) fn outcome_prefer_verified(
    verified_payloads: Vec<ExtractedPayload>,
    fallback_payloads: Vec<ExtractedPayload>,
) -> AnalysisOutcome {
    AnalysisOutcome::from_payloads(payloads_prefer_verified(
        verified_payloads,
        fallback_payloads,
    ))
}

pub(super) fn payloads_prefer_verified(
    verified_payloads: Vec<ExtractedPayload>,
    fallback_payloads: Vec<ExtractedPayload>,
) -> Vec<ExtractedPayload> {
    if verified_payloads.is_empty() {
        fallback_payloads
    } else {
        verified_payloads
    }
}

pub(crate) fn dedupe_payloads(payloads: &mut Vec<ExtractedPayload>) {
    let mut deduped = Vec::new();

    for payload in payloads.drain(..) {
        let already_seen = deduped
            .iter()
            .any(|existing: &ExtractedPayload| same_payload_identity(existing, &payload));

        if !already_seen {
            deduped.push(payload);
        }
    }

    *payloads = deduped;
}

fn same_payload_identity(left: &ExtractedPayload, right: &ExtractedPayload) -> bool {
    left.file.file_name == right.file.file_name
        && left.file.file_type == right.file.file_type
        && left.file.analyzer_name == right.file.analyzer_name
        && left.source == right.source
        && left.bytes == right.bytes
}

fn payload_identifier(payload: &ExtractedPayload) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.file.analyzer_name.as_bytes());
    hasher.update([0]);
    hasher.update(payload.file.file_name.as_bytes());
    hasher.update([0]);
    hasher.update(payload.file.file_type.as_bytes());
    hasher.update([0]);
    hasher.update(match payload.source {
        PayloadSource::VerifiedPacket => b"verified-packet".as_slice(),
        PayloadSource::SignatureScan => b"signature-scan".as_slice(),
    });
    hasher.update([0]);
    hasher.update(&payload.bytes);

    let digest = hasher.finalize();
    format!("payload-{}", digest_to_hex(&digest))
}

fn digest_to_hex(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ExtractedFile, FileSignature, SuspiciousLevel, ValidationStatus};

    #[test]
    fn finalize_extracted_payloads_dedupes_exact_duplicate_payloads_only() {
        let mut first = test_payload(
            "shared_payload.pdf",
            "application/pdf",
            "metadata-analyzer",
            b"%PDF-1.7\nfirst\n%%EOF\n",
            PayloadSource::SignatureScan,
        );
        first.file = first.file.with_id("legacy-first-id");
        let mut exact_duplicate = first.clone();
        exact_duplicate.file = exact_duplicate.file.with_id("legacy-duplicate-id");
        let distinct_same_name = test_payload(
            "shared_payload.pdf",
            "application/pdf",
            "metadata-analyzer",
            b"%PDF-1.7\nsecond\n%%EOF\n",
            PayloadSource::SignatureScan,
        );

        let payloads =
            finalize_extracted_payloads(vec![first, exact_duplicate, distinct_same_name]);

        assert_eq!(payloads.len(), 2);
        assert!(payloads
            .iter()
            .any(|payload| payload.bytes == b"%PDF-1.7\nfirst\n%%EOF\n"));
        assert!(payloads
            .iter()
            .any(|payload| payload.bytes == b"%PDF-1.7\nsecond\n%%EOF\n"));
        assert!(payloads
            .iter()
            .all(|payload| payload.file.id.starts_with("payload-")));
        assert!(payloads
            .iter()
            .all(|payload| payload.file.id != "legacy-first-id"
                && payload.file.id != "legacy-duplicate-id"));
    }

    #[test]
    fn finalize_extracted_payloads_preserves_distinct_verified_payloads_with_same_name() {
        let first = test_payload(
            "shared_payload.pdf",
            "application/pdf",
            "metadata-analyzer",
            b"%PDF-1.7\nverified-first\n%%EOF\n",
            PayloadSource::VerifiedPacket,
        );
        let exact_duplicate = first.clone();
        let distinct_same_name = test_payload(
            "shared_payload.pdf",
            "application/pdf",
            "metadata-analyzer",
            b"%PDF-1.7\nverified-second\n%%EOF\n",
            PayloadSource::VerifiedPacket,
        );
        let signature_only = test_payload(
            "fallback_payload.pdf",
            "application/pdf",
            "metadata-analyzer",
            b"%PDF-1.7\nsignature-only\n%%EOF\n",
            PayloadSource::SignatureScan,
        );

        let payloads = finalize_extracted_payloads(vec![
            first,
            exact_duplicate,
            distinct_same_name,
            signature_only,
        ]);

        assert_eq!(payloads.len(), 2);
        assert!(payloads
            .iter()
            .all(|payload| payload.source == PayloadSource::VerifiedPacket));
        assert!(payloads
            .iter()
            .any(|payload| payload.bytes == b"%PDF-1.7\nverified-first\n%%EOF\n"));
        assert!(payloads
            .iter()
            .any(|payload| payload.bytes == b"%PDF-1.7\nverified-second\n%%EOF\n"));
    }

    #[test]
    fn assign_payload_ids_uses_recovered_bytes_for_same_name_payloads() {
        let mut payloads = vec![
            test_payload(
                "shared_payload.pdf",
                "application/pdf",
                "metadata-analyzer",
                b"%PDF-1.7\nfirst\n%%EOF\n",
                PayloadSource::VerifiedPacket,
            ),
            test_payload(
                "shared_payload.pdf",
                "application/pdf",
                "metadata-analyzer",
                b"%PDF-1.7\nsecond\n%%EOF\n",
                PayloadSource::VerifiedPacket,
            ),
        ];

        assign_payload_ids(&mut payloads);

        assert!(payloads
            .iter()
            .all(|payload| payload.file.id.starts_with("payload-")));
        assert_ne!(payloads[0].file.id, payloads[1].file.id);
    }

    #[test]
    fn assign_payload_ids_is_stable_for_identical_payload_identity() {
        let mut first = test_payload(
            "stable_payload.pdf",
            "application/pdf",
            "metadata-analyzer",
            b"%PDF-1.7\nstable\n%%EOF\n",
            PayloadSource::VerifiedPacket,
        );
        first.file = first.file.with_id("legacy-first-id");
        let mut second = first.clone();
        second.file = second.file.with_id("legacy-second-id");
        let mut payloads = vec![first, second];

        assign_payload_ids(&mut payloads);

        assert_eq!(payloads[0].file.id, payloads[1].file.id);
        assert_ne!(payloads[0].file.id, "legacy-first-id");
        assert_ne!(payloads[1].file.id, "legacy-second-id");
        assert!(payloads[0].file.id.starts_with("payload-"));
        assert_eq!(
            payloads[0].file.id,
            "payload-ed6da7d20110773116ecc3b7c3e7d17cd06d1e831ddc1cf1cd9ad65079d6f46f"
        );
    }

    #[test]
    fn assign_payload_ids_separates_payload_source_and_analyzer_identity() {
        let bytes = b"%PDF-1.7\nsame bytes different evidence\n%%EOF\n";
        let mut payloads = vec![
            test_payload(
                "shared_payload.pdf",
                "application/pdf",
                "metadata-analyzer",
                bytes,
                PayloadSource::VerifiedPacket,
            ),
            test_payload(
                "shared_payload.pdf",
                "application/pdf",
                "metadata-analyzer",
                bytes,
                PayloadSource::SignatureScan,
            ),
            test_payload(
                "shared_payload.pdf",
                "application/pdf",
                "png-container-analyzer",
                bytes,
                PayloadSource::VerifiedPacket,
            ),
        ];

        assign_payload_ids(&mut payloads);

        assert_ne!(payloads[0].file.id, payloads[1].file.id);
        assert_ne!(payloads[0].file.id, payloads[2].file.id);
        assert_ne!(payloads[1].file.id, payloads[2].file.id);
    }

    #[test]
    fn assign_payload_ids_separates_embedded_name_and_file_type() {
        let bytes = b"same bytes from different embedded metadata";
        let mut payloads = vec![
            test_payload(
                "shared_payload.pdf",
                "application/pdf",
                "metadata-analyzer",
                bytes,
                PayloadSource::VerifiedPacket,
            ),
            test_payload(
                "renamed_payload.pdf",
                "application/pdf",
                "metadata-analyzer",
                bytes,
                PayloadSource::VerifiedPacket,
            ),
            test_payload(
                "shared_payload.pdf",
                "application/octet-stream",
                "metadata-analyzer",
                bytes,
                PayloadSource::VerifiedPacket,
            ),
        ];

        assign_payload_ids(&mut payloads);

        assert_ne!(payloads[0].file.id, payloads[1].file.id);
        assert_ne!(payloads[0].file.id, payloads[2].file.id);
        assert_ne!(payloads[1].file.id, payloads[2].file.id);
    }

    fn test_payload(
        file_name: &str,
        file_type: &str,
        analyzer_name: &str,
        bytes: &[u8],
        source: PayloadSource,
    ) -> ExtractedPayload {
        ExtractedPayload {
            file: ExtractedFile::new(
                file_name,
                analyzer_name,
                SuspiciousLevel::High,
                ValidationStatus::Validated,
                "test payload",
                bytes.len() as u64,
                file_type,
                FileSignature::known("PDF document", "pdf", "application/pdf", "25 50 44 46"),
            ),
            bytes: bytes.to_vec(),
            source,
        }
    }
}
