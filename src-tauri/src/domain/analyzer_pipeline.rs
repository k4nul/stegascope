use super::analyzer::{
    AnalysisError, AnalysisOutcome, EmbeddedSignatureAnalyzer, ExtractedPayload, FileAnalyzer,
    JpegSegmentAnalyzer, LoadedMedia, Lsb2bppAnalyzer, LsbAnalyzer, MetadataAnalyzer,
    PayloadSource, PngContainerAnalyzer, WavPcmLsbAnalyzer,
};

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

    payloads
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

pub(super) fn dedupe_payloads(payloads: &mut Vec<ExtractedPayload>) {
    let mut deduped = Vec::new();

    for payload in payloads.drain(..) {
        let already_seen = deduped.iter().any(|existing: &ExtractedPayload| {
            existing.file.file_name == payload.file.file_name
                && existing.file.file_type == payload.file.file_type
                && existing.file.analyzer_name == payload.file.analyzer_name
        });

        if !already_seen {
            deduped.push(payload);
        }
    }

    *payloads = deduped;
}
