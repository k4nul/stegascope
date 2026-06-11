use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::{
    ExtractedFile, FileSignature, MediaFileInfo, SuspiciousLevel, ValidationStatus,
};

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
    pub extracted_payloads: Vec<ExtractedPayload>,
}

impl AnalysisOutcome {
    pub fn new(extracted_files: Vec<ExtractedFile>) -> Self {
        Self {
            extracted_files,
            extracted_payloads: Vec::new(),
        }
    }

    pub fn from_payloads(mut extracted_payloads: Vec<ExtractedPayload>) -> Self {
        dedupe_payloads(&mut extracted_payloads);
        let extracted_files = extracted_payloads
            .iter()
            .map(|payload| payload.file.clone())
            .collect();

        Self {
            extracted_files,
            extracted_payloads,
        }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedPayload {
    pub file: ExtractedFile,
    pub bytes: Vec<u8>,
    pub source: PayloadSource,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PayloadSource {
    VerifiedPacket,
    SignatureScan,
}

#[derive(Debug)]
pub struct MetadataAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for MetadataAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("metadata-analyzer")
                .with_version("0.1.0")
                .with_description("Scans metadata chunks and tagged side channels."),
        }
    }
}

impl FileAnalyzer for MetadataAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        Ok(AnalysisOutcome::from_payloads(extract_metadata_payloads(
            media,
            self.name(),
        )))
    }
}

#[derive(Debug)]
pub struct JpegSegmentAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for JpegSegmentAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("jpeg-segment-analyzer")
                .with_version("0.1.0")
                .with_description(
                    "Scans JPEG COM/APP segments and trailing after-EOI payload data.",
                ),
        }
    }
}

impl FileAnalyzer for JpegSegmentAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        Ok(AnalysisOutcome::from_payloads(
            extract_jpeg_segment_payloads(media, self.name()),
        ))
    }
}

#[derive(Debug)]
pub struct EmbeddedSignatureAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for EmbeddedSignatureAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("embedded-signature-analyzer")
                .with_version("0.1.0")
                .with_description("Looks for embedded file signatures after the media header."),
        }
    }
}

impl FileAnalyzer for EmbeddedSignatureAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        Ok(AnalysisOutcome::from_payloads(
            extract_embedded_signature_payloads(media, self.name()),
        ))
    }
}

const MAX_LSB_BYTES_TO_SCAN: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BitPacking {
    MsbFirst,
    LsbFirst,
}

impl BitPacking {
    fn file_label(self) -> &'static str {
        match self {
            Self::MsbFirst => "msb_first",
            Self::LsbFirst => "lsb_first",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lsb2bppStrategy {
    RgPixel,
    RbPixel,
    GbPixel,
    ChannelLowHigh,
    ChannelHighLow,
    Matrix2x3Rgb,
    Matrix2x3Rbg,
    Matrix2x3Grb,
    Matrix2x3Gbr,
    Matrix2x3Brg,
    Matrix2x3Bgr,
}

impl Lsb2bppStrategy {
    fn file_label(self) -> &'static str {
        match self {
            Self::RgPixel => "rg_pixel",
            Self::RbPixel => "rb_pixel",
            Self::GbPixel => "gb_pixel",
            Self::ChannelLowHigh => "channel_low_high",
            Self::ChannelHighLow => "channel_high_low",
            Self::Matrix2x3Rgb => "matrix_2x3_rgb",
            Self::Matrix2x3Rbg => "matrix_2x3_rbg",
            Self::Matrix2x3Grb => "matrix_2x3_grb",
            Self::Matrix2x3Gbr => "matrix_2x3_gbr",
            Self::Matrix2x3Brg => "matrix_2x3_brg",
            Self::Matrix2x3Bgr => "matrix_2x3_bgr",
        }
    }

    fn matrix_channel_order(self) -> Option<[usize; 3]> {
        match self {
            Self::Matrix2x3Rgb => Some([0, 1, 2]),
            Self::Matrix2x3Rbg => Some([0, 2, 1]),
            Self::Matrix2x3Grb => Some([1, 0, 2]),
            Self::Matrix2x3Gbr => Some([1, 2, 0]),
            Self::Matrix2x3Brg => Some([2, 0, 1]),
            Self::Matrix2x3Bgr => Some([2, 1, 0]),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct LsbAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for LsbAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("lsb-analyzer")
                .with_version("0.1.0")
                .with_description(
                    "Extracts RGB least-significant-bit streams from decoded images.",
                ),
        }
    }
}

impl FileAnalyzer for LsbAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        if !media.source.file_type.starts_with("image/") {
            return Ok(AnalysisOutcome::default());
        }

        let image = image::load_from_memory(&media.bytes).map_err(|error| {
            AnalysisError::ExtractionFailed(format!(
                "failed to decode image for LSB analysis: {error}"
            ))
        })?;
        let rgba = image.to_rgba8();
        let bits = extract_rgb_lsb_bits(&rgba);

        if bits.len() < 8 {
            return Ok(AnalysisOutcome::default());
        }

        let mut verified_payloads = Vec::new();
        let mut fallback_payloads = Vec::new();

        for bit_packing in [BitPacking::MsbFirst, BitPacking::LsbFirst] {
            let decoded = bits_to_bytes(&bits, bit_packing, MAX_LSB_BYTES_TO_SCAN);
            let verified = find_stegascope_packet_candidates(&decoded, self.name());

            if verified.is_empty() {
                fallback_payloads.extend(find_lsb_signature_payload_candidates(
                    &decoded,
                    bit_packing,
                    "lsb",
                    self.name(),
                ));
            } else {
                verified_payloads.extend(verified);
            }
        }

        Ok(outcome_prefer_verified(
            verified_payloads,
            fallback_payloads,
        ))
    }
}

#[derive(Debug)]
pub struct Lsb2bppAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for Lsb2bppAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("lsb-2bpp-analyzer")
                .with_version("0.1.0")
                .with_description("Extracts two-bit-per-pixel LSB streams from decoded images."),
        }
    }
}

impl FileAnalyzer for Lsb2bppAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        if !media.source.file_type.starts_with("image/") {
            return Ok(AnalysisOutcome::default());
        }

        let image = image::load_from_memory(&media.bytes).map_err(|error| {
            AnalysisError::ExtractionFailed(format!(
                "failed to decode image for 2bpp LSB analysis: {error}"
            ))
        })?;
        let rgba = image.to_rgba8();
        let mut verified_payloads = Vec::new();
        let mut fallback_payloads = Vec::new();

        for strategy in [
            Lsb2bppStrategy::RgPixel,
            Lsb2bppStrategy::RbPixel,
            Lsb2bppStrategy::GbPixel,
            Lsb2bppStrategy::ChannelLowHigh,
            Lsb2bppStrategy::ChannelHighLow,
            Lsb2bppStrategy::Matrix2x3Rgb,
            Lsb2bppStrategy::Matrix2x3Rbg,
            Lsb2bppStrategy::Matrix2x3Grb,
            Lsb2bppStrategy::Matrix2x3Gbr,
            Lsb2bppStrategy::Matrix2x3Brg,
            Lsb2bppStrategy::Matrix2x3Bgr,
        ] {
            let bits = extract_lsb2bpp_bits(&rgba, strategy);
            if bits.len() < 8 {
                continue;
            }

            for bit_packing in [BitPacking::MsbFirst, BitPacking::LsbFirst] {
                let decoded = bits_to_bytes(&bits, bit_packing, MAX_LSB_BYTES_TO_SCAN);
                let prefix = format!("lsb2bpp_{}", strategy.file_label());
                let verified = find_stegascope_packet_candidates(&decoded, self.name());

                if verified.is_empty() {
                    fallback_payloads.extend(find_lsb_signature_payload_candidates(
                        &decoded,
                        bit_packing,
                        &prefix,
                        self.name(),
                    ));
                } else {
                    verified_payloads.extend(verified);
                }
            }
        }

        Ok(outcome_prefer_verified(
            verified_payloads,
            fallback_payloads,
        ))
    }
}

pub fn default_analyzers() -> Vec<Box<dyn FileAnalyzer>> {
    vec![
        Box::<MetadataAnalyzer>::default(),
        Box::<JpegSegmentAnalyzer>::default(),
        Box::<EmbeddedSignatureAnalyzer>::default(),
        Box::<LsbAnalyzer>::default(),
        Box::<Lsb2bppAnalyzer>::default(),
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

fn outcome_prefer_verified(
    verified_payloads: Vec<ExtractedPayload>,
    fallback_payloads: Vec<ExtractedPayload>,
) -> AnalysisOutcome {
    AnalysisOutcome::from_payloads(payloads_prefer_verified(
        verified_payloads,
        fallback_payloads,
    ))
}

fn payloads_prefer_verified(
    verified_payloads: Vec<ExtractedPayload>,
    fallback_payloads: Vec<ExtractedPayload>,
) -> Vec<ExtractedPayload> {
    if verified_payloads.is_empty() {
        fallback_payloads
    } else {
        verified_payloads
    }
}

fn extract_rgb_lsb_bits(image: &image::RgbaImage) -> Vec<u8> {
    let mut bits = Vec::with_capacity(image.width() as usize * image.height() as usize * 3);

    for pixel in image.pixels() {
        for channel in &pixel.0[..3] {
            bits.push(*channel & 1);
        }
    }

    bits
}

fn extract_lsb2bpp_bits(image: &image::RgbaImage, strategy: Lsb2bppStrategy) -> Vec<u8> {
    let bits_per_pixel = match strategy {
        Lsb2bppStrategy::RgPixel
        | Lsb2bppStrategy::RbPixel
        | Lsb2bppStrategy::GbPixel
        | Lsb2bppStrategy::Matrix2x3Rgb
        | Lsb2bppStrategy::Matrix2x3Rbg
        | Lsb2bppStrategy::Matrix2x3Grb
        | Lsb2bppStrategy::Matrix2x3Gbr
        | Lsb2bppStrategy::Matrix2x3Brg
        | Lsb2bppStrategy::Matrix2x3Bgr => 2,
        Lsb2bppStrategy::ChannelLowHigh | Lsb2bppStrategy::ChannelHighLow => 6,
    };
    let mut bits =
        Vec::with_capacity(image.width() as usize * image.height() as usize * bits_per_pixel);

    for pixel in image.pixels() {
        match strategy {
            Lsb2bppStrategy::RgPixel => {
                bits.push(pixel.0[0] & 1);
                bits.push(pixel.0[1] & 1);
            }
            Lsb2bppStrategy::RbPixel => {
                bits.push(pixel.0[0] & 1);
                bits.push(pixel.0[2] & 1);
            }
            Lsb2bppStrategy::GbPixel => {
                bits.push(pixel.0[1] & 1);
                bits.push(pixel.0[2] & 1);
            }
            Lsb2bppStrategy::ChannelLowHigh => {
                for channel in &pixel.0[..3] {
                    bits.push(*channel & 1);
                    bits.push((*channel >> 1) & 1);
                }
            }
            Lsb2bppStrategy::ChannelHighLow => {
                for channel in &pixel.0[..3] {
                    bits.push((*channel >> 1) & 1);
                    bits.push(*channel & 1);
                }
            }
            Lsb2bppStrategy::Matrix2x3Rgb
            | Lsb2bppStrategy::Matrix2x3Rbg
            | Lsb2bppStrategy::Matrix2x3Grb
            | Lsb2bppStrategy::Matrix2x3Gbr
            | Lsb2bppStrategy::Matrix2x3Brg
            | Lsb2bppStrategy::Matrix2x3Bgr => {
                if let Some([first, second, third]) = strategy.matrix_channel_order() {
                    let b0 = pixel.0[first] & 1;
                    let b1 = pixel.0[second] & 1;
                    let b2 = pixel.0[third] & 1;

                    bits.push(b0 ^ b1);
                    bits.push(b1 ^ b2);
                }
            }
        }
    }

    bits
}

fn bits_to_bytes(bits: &[u8], bit_packing: BitPacking, max_bytes: usize) -> Vec<u8> {
    let byte_count = (bits.len() / 8).min(max_bytes);
    let mut bytes = Vec::with_capacity(byte_count);

    for chunk in bits.chunks_exact(8).take(byte_count) {
        let value = match bit_packing {
            BitPacking::MsbFirst => chunk.iter().fold(0_u8, |acc, bit| (acc << 1) | (*bit & 1)),
            BitPacking::LsbFirst => chunk
                .iter()
                .enumerate()
                .fold(0_u8, |acc, (bit_index, bit)| {
                    acc | ((*bit & 1) << bit_index)
                }),
        };
        bytes.push(value);
    }

    bytes
}

fn find_lsb_signature_payload_candidates(
    bytes: &[u8],
    bit_packing: BitPacking,
    prefix: &str,
    analyzer_name: &str,
) -> Vec<ExtractedPayload> {
    signature_payload_candidates(
        bytes,
        Some(bit_packing),
        prefix,
        0,
        SuspiciousLevel::Critical,
        analyzer_name,
    )
}

fn extract_embedded_signature_payloads(
    media: &LoadedMedia,
    analyzer_name: &str,
) -> Vec<ExtractedPayload> {
    signature_payload_candidates(
        &media.bytes,
        None,
        "embedded",
        media_header_guard(&media.source.file_type) + 1,
        SuspiciousLevel::High,
        analyzer_name,
    )
}

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1A\n";
const JPEG_SOI: &[u8; 2] = b"\xFF\xD8";
const JPEG_EOI: &[u8; 2] = b"\xFF\xD9";

fn extract_metadata_payloads(media: &LoadedMedia, analyzer_name: &str) -> Vec<ExtractedPayload> {
    if !media.bytes.starts_with(PNG_SIGNATURE) {
        return Vec::new();
    }

    let mut verified_payloads = Vec::new();
    let mut fallback_payloads = Vec::new();

    for chunk in png_metadata_chunks(&media.bytes) {
        verified_payloads.extend(find_stegascope_packet_candidates(chunk.data, analyzer_name));

        let prefix = format!(
            "metadata_png_{}_chunk_{}",
            png_chunk_type_label(chunk.kind),
            chunk.index
        );
        fallback_payloads.extend(signature_payload_candidates(
            chunk.data,
            None,
            &prefix,
            0,
            SuspiciousLevel::High,
            analyzer_name,
        ));
    }

    payloads_prefer_verified(verified_payloads, fallback_payloads)
}

fn extract_jpeg_segment_payloads(
    media: &LoadedMedia,
    analyzer_name: &str,
) -> Vec<ExtractedPayload> {
    if !media.bytes.starts_with(JPEG_SOI) {
        return Vec::new();
    }

    let mut verified_payloads = Vec::new();
    let mut fallback_payloads = Vec::new();

    for segment in jpeg_payload_segments(&media.bytes) {
        verified_payloads.extend(find_stegascope_packet_candidates(
            segment.data,
            analyzer_name,
        ));

        let prefix = format!(
            "jpeg_{}_segment_{}",
            jpeg_segment_type_label(segment.marker),
            segment.index
        );
        fallback_payloads.extend(signature_payload_candidates(
            segment.data,
            None,
            &prefix,
            0,
            SuspiciousLevel::High,
            analyzer_name,
        ));
    }

    if let Some(after_eoi) = jpeg_after_eoi_payload(&media.bytes) {
        verified_payloads.extend(find_stegascope_packet_candidates(after_eoi, analyzer_name));
        fallback_payloads.extend(signature_payload_candidates(
            after_eoi,
            None,
            "jpeg_after_eoi",
            0,
            SuspiciousLevel::Critical,
            analyzer_name,
        ));
    }

    payloads_prefer_verified(verified_payloads, fallback_payloads)
}

struct JpegSegment<'a> {
    index: usize,
    marker: u8,
    data: &'a [u8],
}

fn jpeg_payload_segments(bytes: &[u8]) -> Vec<JpegSegment<'_>> {
    if !bytes.starts_with(JPEG_SOI) {
        return Vec::new();
    }

    let mut segments = Vec::new();
    let mut offset = JPEG_SOI.len();
    let mut index = 0;

    while offset < bytes.len() {
        while offset < bytes.len() && bytes[offset] == 0xFF {
            offset += 1;
        }

        if offset >= bytes.len() {
            break;
        }

        let marker = bytes[offset];
        offset += 1;

        if marker == 0xD9 || marker == 0xDA {
            break;
        }

        if marker == 0x00 || jpeg_marker_has_no_payload(marker) {
            continue;
        }

        let Some(length_end) = offset.checked_add(2) else {
            break;
        };
        if length_end > bytes.len() {
            break;
        }

        let segment_length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        if segment_length < 2 {
            break;
        }

        let data_start = length_end;
        let Some(data_end) = data_start.checked_add(segment_length - 2) else {
            break;
        };
        if data_end > bytes.len() {
            break;
        }

        index += 1;
        if is_jpeg_payload_segment(marker) {
            segments.push(JpegSegment {
                index,
                marker,
                data: &bytes[data_start..data_end],
            });
        }

        offset = data_end;
    }

    segments
}

fn jpeg_after_eoi_payload(bytes: &[u8]) -> Option<&[u8]> {
    let eoi_offset = find_signature_offsets(bytes, JPEG_EOI).into_iter().next()?;
    let payload_start = eoi_offset.checked_add(JPEG_EOI.len())?;

    (payload_start < bytes.len()).then_some(&bytes[payload_start..])
}

fn jpeg_marker_has_no_payload(marker: u8) -> bool {
    marker == 0x01 || (0xD0..=0xD8).contains(&marker)
}

fn is_jpeg_payload_segment(marker: u8) -> bool {
    marker == 0xFE || (0xE0..=0xEF).contains(&marker)
}

fn jpeg_segment_type_label(marker: u8) -> &'static str {
    match marker {
        0xFE => "com",
        0xE0 => "app0",
        0xE1 => "app1",
        0xE2 => "app2",
        0xE3 => "app3",
        0xE4 => "app4",
        0xE5 => "app5",
        0xE6 => "app6",
        0xE7 => "app7",
        0xE8 => "app8",
        0xE9 => "app9",
        0xEA => "app10",
        0xEB => "app11",
        0xEC => "app12",
        0xED => "app13",
        0xEE => "app14",
        0xEF => "app15",
        _ => "segment",
    }
}

struct PngChunk<'a> {
    index: usize,
    kind: &'a [u8],
    data: &'a [u8],
}

fn png_metadata_chunks(bytes: &[u8]) -> Vec<PngChunk<'_>> {
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut offset = PNG_SIGNATURE.len();
    let mut index = 0;

    loop {
        let Some(length_end) = offset.checked_add(4) else {
            break;
        };
        let Some(kind_end) = length_end.checked_add(4) else {
            break;
        };
        if kind_end > bytes.len() {
            break;
        }

        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let data_start = kind_end;
        let Some(data_end) = data_start.checked_add(length) else {
            break;
        };
        let Some(next_offset) = data_end.checked_add(4) else {
            break;
        };
        if next_offset > bytes.len() {
            break;
        }

        index += 1;
        let kind = &bytes[length_end..kind_end];
        if is_png_metadata_chunk(kind) {
            chunks.push(PngChunk {
                index,
                kind,
                data: &bytes[data_start..data_end],
            });
        }

        offset = next_offset;
    }

    chunks
}

fn is_png_metadata_chunk(kind: &[u8]) -> bool {
    matches!(kind, b"tEXt" | b"iTXt" | b"zTXt" | b"eXIf")
        || kind.first().is_some_and(u8::is_ascii_lowercase)
}

fn png_chunk_type_label(kind: &[u8]) -> String {
    kind.iter()
        .map(|byte| {
            let character = *byte as char;
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn signature_payload_candidates(
    bytes: &[u8],
    bit_packing: Option<BitPacking>,
    prefix: &str,
    min_offset: usize,
    suspicious_level: SuspiciousLevel,
    analyzer_name: &str,
) -> Vec<ExtractedPayload> {
    let mut payloads = Vec::new();

    for signature in KNOWN_FILE_SIGNATURES
        .iter()
        .filter(|signature| signature.magic.len() >= 3)
    {
        for offset in find_signature_offsets(bytes, signature.magic)
            .into_iter()
            .take(3)
        {
            if offset < min_offset {
                continue;
            }

            let file_name_base = match bit_packing {
                Some(bit_packing) => {
                    format!("{prefix}_{}_payload_{offset}", bit_packing.file_label())
                }
                None => format!("{prefix}_payload_{offset}"),
            };
            let payload_bytes = bytes[offset..].to_vec();
            let Some(validation_note) = validate_signature_candidate(&payload_bytes, signature)
            else {
                continue;
            };

            payloads.push(extracted_payload_from_bytes(
                file_name_base,
                suspicious_level.clone(),
                analyzer_name,
                payload_bytes,
                PayloadSource::SignatureScan,
                ValidationStatus::Validated,
                validation_note,
            ));
        }
    }

    payloads
}

const STEGASCOPE_PACKET_MAGIC: &[u8; 8] = b"SS2X3ME1";
const STEGASCOPE_PACKET_HEADER_LEN: usize = 50;

fn find_stegascope_packet_candidates(bytes: &[u8], analyzer_name: &str) -> Vec<ExtractedPayload> {
    let mut payloads = Vec::new();

    for offset in find_signature_offsets(bytes, STEGASCOPE_PACKET_MAGIC)
        .into_iter()
        .take(3)
    {
        let Some(packet) = parse_stegascope_packet(bytes, offset) else {
            continue;
        };

        payloads.push(extracted_payload_from_bytes(
            packet.file_name_base,
            SuspiciousLevel::Critical,
            analyzer_name,
            packet.payload,
            PayloadSource::VerifiedPacket,
            ValidationStatus::Verified,
            "StegaScope packet length and SHA-256 hash verified",
        ));
    }

    payloads
}

struct ParsedStegascopePacket {
    file_name_base: String,
    payload: Vec<u8>,
}

fn parse_stegascope_packet(bytes: &[u8], offset: usize) -> Option<ParsedStegascopePacket> {
    let header_end = offset.checked_add(STEGASCOPE_PACKET_HEADER_LEN)?;
    if header_end > bytes.len() {
        return None;
    }

    if &bytes[offset..offset + STEGASCOPE_PACKET_MAGIC.len()] != STEGASCOPE_PACKET_MAGIC {
        return None;
    }

    let name_len = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
    let payload_len = u64::from_be_bytes([
        bytes[offset + 10],
        bytes[offset + 11],
        bytes[offset + 12],
        bytes[offset + 13],
        bytes[offset + 14],
        bytes[offset + 15],
        bytes[offset + 16],
        bytes[offset + 17],
    ]) as usize;
    let expected_hash = &bytes[offset + 18..offset + 50];
    let name_start = header_end;
    let name_end = name_start.checked_add(name_len)?;
    let payload_start = name_end;
    let payload_end = payload_start.checked_add(payload_len)?;

    if payload_end > bytes.len() {
        return None;
    }

    let embedded_name = std::str::from_utf8(&bytes[name_start..name_end])
        .ok()
        .map(sanitize_file_name)?;
    let payload = bytes[payload_start..payload_end].to_vec();
    let actual_hash = Sha256::digest(&payload);

    if actual_hash.as_slice() != expected_hash {
        return None;
    }

    let file_name_base = if embedded_name.trim().is_empty() {
        "extracted_payload".to_string()
    } else {
        embedded_name
    };

    Some(ParsedStegascopePacket {
        file_name_base,
        payload,
    })
}

fn sanitize_file_name(file_name: &str) -> String {
    file_name
        .chars()
        .map(|character| match character {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            character if character.is_control() => '_',
            character => character,
        })
        .collect()
}

#[derive(Clone, Copy)]
struct KnownFileSignature {
    magic: &'static [u8],
    label: &'static str,
    extension: &'static str,
    mime_type: &'static str,
}

const KNOWN_FILE_SIGNATURES: &[KnownFileSignature] = &[
    KnownFileSignature {
        magic: b"\x89PNG\r\n\x1A\n",
        label: "PNG image",
        extension: "png",
        mime_type: "image/png",
    },
    KnownFileSignature {
        magic: b"\xFF\xD8\xFF",
        label: "JPEG image",
        extension: "jpg",
        mime_type: "image/jpeg",
    },
    KnownFileSignature {
        magic: b"GIF8",
        label: "GIF image",
        extension: "gif",
        mime_type: "image/gif",
    },
    KnownFileSignature {
        magic: b"%PDF",
        label: "PDF document",
        extension: "pdf",
        mime_type: "application/pdf",
    },
    KnownFileSignature {
        magic: b"PK\x03\x04",
        label: "ZIP archive",
        extension: "zip",
        mime_type: "application/zip",
    },
    KnownFileSignature {
        magic: b"Rar!\x1A\x07\x00",
        label: "RAR archive",
        extension: "rar",
        mime_type: "application/vnd.rar",
    },
    KnownFileSignature {
        magic: b"7z\xBC\xAF\x27\x1C",
        label: "7-Zip archive",
        extension: "7z",
        mime_type: "application/x-7z-compressed",
    },
    KnownFileSignature {
        magic: b"BM",
        label: "BMP image",
        extension: "bmp",
        mime_type: "image/bmp",
    },
    KnownFileSignature {
        magic: b"ID3",
        label: "MP3 audio",
        extension: "mp3",
        mime_type: "audio/mpeg",
    },
    KnownFileSignature {
        magic: b"fLaC",
        label: "FLAC audio",
        extension: "flac",
        mime_type: "audio/flac",
    },
    KnownFileSignature {
        magic: b"OggS",
        label: "Ogg media",
        extension: "ogg",
        mime_type: "application/ogg",
    },
];

fn validate_signature_candidate(bytes: &[u8], signature: &KnownFileSignature) -> Option<String> {
    match signature.extension {
        "png" | "jpg" | "gif" => validate_image_payload(bytes, signature.label),
        "pdf" => validate_pdf_payload(bytes),
        "zip" => validate_zip_payload(bytes),
        "rar" => validate_minimum_length(bytes, signature.magic.len() + 16, signature.label),
        "7z" => validate_minimum_length(bytes, 32, signature.label),
        "mp3" => validate_mp3_payload(bytes),
        "flac" => validate_minimum_length(bytes, 42, signature.label),
        "ogg" => validate_ogg_payload(bytes),
        _ => validate_minimum_length(bytes, signature.magic.len(), signature.label),
    }
}

fn validate_image_payload(bytes: &[u8], label: &str) -> Option<String> {
    image::load_from_memory(bytes)
        .map(|_| format!("{label} decoder accepted the extracted bytes"))
        .ok()
}

fn validate_pdf_payload(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"%PDF-") && find_signature_offsets(bytes, b"%%EOF").first().is_some() {
        Some("PDF header and EOF marker found".to_string())
    } else {
        None
    }
}

fn validate_zip_payload(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"PK\x03\x04")
        && (find_signature_offsets(bytes, b"PK\x05\x06")
            .first()
            .is_some()
            || find_signature_offsets(bytes, b"PK\x06\x06")
                .first()
                .is_some())
    {
        Some("ZIP local header and central directory marker found".to_string())
    } else {
        None
    }
}

fn validate_mp3_payload(bytes: &[u8]) -> Option<String> {
    if !bytes.starts_with(b"ID3") || bytes.len() < 10 {
        return None;
    }

    let tag_size = synchsafe_u32(&bytes[6..10])? as usize;
    let search_start = 10usize.saturating_add(tag_size).min(bytes.len());
    let frame_count = count_mpeg_frame_syncs(&bytes[search_start..]);

    if frame_count >= 2 {
        Some("ID3 tag followed by repeated MPEG frame sync markers".to_string())
    } else {
        None
    }
}

fn validate_ogg_payload(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 27 || !bytes.starts_with(b"OggS") || bytes[4] != 0 {
        return None;
    }

    let segment_count = bytes[26] as usize;
    if bytes.len() >= 27 + segment_count {
        Some("Ogg capture page header is structurally valid".to_string())
    } else {
        None
    }
}

fn validate_minimum_length(bytes: &[u8], min_len: usize, label: &str) -> Option<String> {
    (bytes.len() >= min_len).then(|| format!("{label} signature and minimum length verified"))
}

fn synchsafe_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 4 || bytes.iter().any(|byte| byte & 0x80 != 0) {
        return None;
    }

    Some(
        ((bytes[0] as u32) << 21)
            | ((bytes[1] as u32) << 14)
            | ((bytes[2] as u32) << 7)
            | bytes[3] as u32,
    )
}

fn count_mpeg_frame_syncs(bytes: &[u8]) -> usize {
    bytes
        .windows(2)
        .take(64 * 1024)
        .filter(|window| window[0] == 0xFF && (window[1] & 0xE0) == 0xE0)
        .take(2)
        .count()
}

fn extracted_payload_from_bytes(
    file_name_base: impl AsRef<str>,
    suspicious_level: SuspiciousLevel,
    analyzer_name: &str,
    bytes: Vec<u8>,
    source: PayloadSource,
    validation_status: ValidationStatus,
    validation_note: impl Into<String>,
) -> ExtractedPayload {
    let file_signature = detect_file_signature(&bytes);
    let file_name = file_name_for_signature(file_name_base.as_ref(), &file_signature);
    let file_type = file_signature
        .mime_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    ExtractedPayload {
        file: ExtractedFile::new(
            file_name,
            analyzer_name,
            suspicious_level,
            validation_status,
            validation_note,
            bytes.len() as u64,
            file_type,
            file_signature,
        ),
        bytes,
        source,
    }
}

fn detect_file_signature(bytes: &[u8]) -> FileSignature {
    let header_hex = header_hex(bytes);

    for signature in KNOWN_FILE_SIGNATURES {
        if bytes.starts_with(signature.magic) {
            return FileSignature::known(
                signature.label,
                signature.extension,
                signature.mime_type,
                header_hex,
            );
        }
    }

    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
        return FileSignature::known("WAV audio", "wav", "audio/wav", header_hex);
    }

    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"AVI " {
        return FileSignature::known("AVI video", "avi", "video/x-msvideo", header_hex);
    }

    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return FileSignature::known("WebP image", "webp", "image/webp", header_hex);
    }

    if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        return FileSignature::known("ISO base media", "mp4", "video/mp4", header_hex);
    }

    FileSignature::unknown(header_hex)
}

fn file_name_for_signature(file_name_base: &str, file_signature: &FileSignature) -> String {
    let sanitized = sanitize_file_name(file_name_base);
    let sanitized = sanitized.trim();
    let base = if sanitized.is_empty() {
        "extracted_payload"
    } else {
        sanitized
    };
    let stem = file_stem_without_extension(base);

    match &file_signature.extension {
        Some(extension) => format!("{stem}.{extension}"),
        None => stem.to_string(),
    }
}

fn file_stem_without_extension(file_name: &str) -> &str {
    match file_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.trim().is_empty() && !extension.trim().is_empty() => stem,
        _ => file_name,
    }
}

fn header_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "empty".to_string();
    }

    bytes
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn dedupe_payloads(payloads: &mut Vec<ExtractedPayload>) {
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

fn find_signature_offsets(bytes: &[u8], signature: &[u8]) -> Vec<usize> {
    if signature.is_empty() || bytes.len() < signature.len() {
        return Vec::new();
    }

    bytes
        .windows(signature.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == signature).then_some(offset))
        .collect()
}

fn media_header_guard(file_type: &str) -> usize {
    if file_type.starts_with("image/") {
        32
    } else if file_type.starts_with("audio/") {
        16
    } else if file_type.starts_with("video/") {
        16
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use image::ImageEncoder;

    #[test]
    fn lsb_analyzer_extracts_known_file_signature_from_image_lsb_stream() {
        let payload = valid_pdf_payload();
        let bytes = png_with_lsb_payload(payload, BitPacking::MsbFirst);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = LsbAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "lsb_msb_first_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
        }));
    }

    #[test]
    fn lsb_analyzer_ignores_non_image_media() {
        let media = LoadedMedia {
            source: MediaFileInfo::new("sample.wav", 8, "audio/wav"),
            bytes: valid_pdf_payload().to_vec(),
        };

        let outcome = LsbAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
    }

    #[test]
    fn metadata_analyzer_extracts_packet_payload_from_png_text_chunk() {
        let secret = valid_pdf_payload();
        let packet = stegascope_packet("case_note.pdf", secret);
        let bytes = png_with_text_chunk(b"Comment", &packet);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "case_note.pdf")
            .expect("expected metadata packet payload");

        assert_eq!(payload.file.analyzer_name, "metadata-analyzer");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.file_size_bytes, secret.len() as u64);
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn metadata_analyzer_extracts_valid_signature_from_png_text_chunk() {
        let bytes = png_with_text_chunk(b"Comment", valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
        let file = outcome
            .extracted_files
            .iter()
            .find(|file| file.file_type == "application/pdf")
            .expect("expected metadata signature payload");

        assert!(file.file_name.starts_with("metadata_png_text_chunk_"));
        assert!(file.file_name.ends_with("_payload_8.pdf"));
        assert_eq!(file.analyzer_name, "metadata-analyzer");
        assert_eq!(file.suspicious_level, SuspiciousLevel::High);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn metadata_analyzer_ignores_non_png_media() {
        let media = LoadedMedia {
            source: MediaFileInfo::new(
                "carrier.bin",
                valid_pdf_payload().len() as u64,
                "application/octet-stream",
            ),
            bytes: valid_pdf_payload().to_vec(),
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
        assert!(outcome.extracted_payloads.is_empty());
    }

    #[test]
    fn jpeg_segment_analyzer_extracts_packet_payload_from_comment_segment() {
        let secret = valid_pdf_payload();
        let packet = stegascope_packet("jpeg_note.pdf", secret);
        let bytes = jpeg_with_comment_segment(&packet);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "jpeg_note.pdf")
            .expect("expected JPEG COM packet payload");

        assert_eq!(payload.file.analyzer_name, "jpeg-segment-analyzer");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.file_size_bytes, secret.len() as u64);
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn jpeg_segment_analyzer_extracts_valid_signature_after_eoi() {
        let bytes = jpeg_with_after_eoi_payload(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();
        let file = outcome
            .extracted_files
            .iter()
            .find(|file| file.file_name == "jpeg_after_eoi_payload_0.pdf")
            .expect("expected after-EOI PDF payload");

        assert_eq!(file.analyzer_name, "jpeg-segment-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn lsb_2bpp_analyzer_extracts_known_signature_from_two_pixel_channels() {
        let payload = valid_pdf_payload();
        let bytes = png_with_rg_2bpp_payload(payload, BitPacking::MsbFirst);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = Lsb2bppAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "lsb2bpp_rg_pixel_msb_first_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
        }));
    }

    #[test]
    fn lsb_2bpp_analyzer_extracts_2x3_matrix_embedded_signature() {
        let payload = valid_pdf_payload();
        let bytes = png_with_2x3_matrix_payload(payload, BitPacking::MsbFirst);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = Lsb2bppAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "lsb2bpp_matrix_2x3_rgb_msb_first_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
        }));
    }

    #[test]
    fn lsb_2bpp_analyzer_extracts_2x3_matrix_packet_payload_bytes() {
        let secret = b"\x89PNG\r\n\x1A\nblueprint-bytes";
        let packet = stegascope_packet("secret_blueprint.png", secret);
        let bytes = png_with_2x3_matrix_payload(&packet, BitPacking::MsbFirst);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = Lsb2bppAnalyzer::default().analyze(&media).unwrap();
        let payloads = extract_payload_candidates(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "secret_blueprint.png"
                && file.file_type == "image/png"
                && file.file_size_bytes == secret.len() as u64
        }));
        assert!(payloads.iter().any(|payload| {
            payload.file.file_name == "secret_blueprint.png" && payload.bytes == secret
        }));
    }

    #[test]
    fn lsb_2bpp_analyzer_names_packet_without_filename_from_payload_signature() {
        let secret = b"\x89PNG\r\n\x1A\nnameless-blueprint-bytes";
        let packet = stegascope_packet("", secret);
        let bytes = png_with_2x3_matrix_payload(&packet, BitPacking::MsbFirst);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let payloads = extract_payload_candidates(&media).unwrap();

        assert!(payloads.iter().any(|payload| {
            payload.file.file_name == "extracted_payload.png"
                && payload.file.analyzer_name == "lsb-2bpp-analyzer"
                && payload.file.file_type == "image/png"
                && payload.file.file_signature.is_known
                && payload.file.file_signature.extension.as_deref() == Some("png")
                && payload.bytes == secret
        }));
    }

    #[test]
    fn lsb_2bpp_analyzer_leaves_unknown_signature_payload_without_extension() {
        let secret = b"\x01\x02\x03\x04unknown-binary-payload";
        let packet = stegascope_packet("mystery_payload.png", secret);
        let bytes = png_with_2x3_matrix_payload(&packet, BitPacking::MsbFirst);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let payloads = extract_payload_candidates(&media).unwrap();

        assert!(payloads.iter().any(|payload| {
            payload.file.file_name == "mystery_payload"
                && payload.file.analyzer_name == "lsb-2bpp-analyzer"
                && payload.file.file_type == "application/octet-stream"
                && !payload.file.file_signature.is_known
                && payload.file.file_signature.extension.is_none()
                && payload.bytes == secret
        }));
    }

    #[test]
    fn embedded_signature_analyzer_rejects_invalid_mp3_candidate() {
        let bytes = b"carrier-header-padding-ID3not-a-real-mp3-file".to_vec();
        let media = LoadedMedia {
            source: MediaFileInfo::new(
                "carrier.bin",
                bytes.len() as u64,
                "application/octet-stream",
            ),
            bytes,
        };

        let outcome = EmbeddedSignatureAnalyzer::default()
            .analyze(&media)
            .unwrap();

        assert!(outcome.extracted_files.is_empty());
    }

    #[test]
    fn verified_packet_suppresses_signature_only_candidates() {
        let secret = b"\x89PNG\r\n\x1A\nverified-blueprint-bytes";
        let packet = stegascope_packet("", secret);
        let mut bytes = png_with_2x3_matrix_payload(&packet, BitPacking::MsbFirst);
        bytes.extend_from_slice(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let payloads = extract_payload_candidates(&media).unwrap();

        assert!(payloads.iter().any(|payload| {
            payload.file.file_name == "extracted_payload.png"
                && payload.source == PayloadSource::VerifiedPacket
        }));
        assert!(!payloads
            .iter()
            .any(|payload| payload.source == PayloadSource::SignatureScan));
    }

    fn valid_pdf_payload() -> &'static [u8] {
        b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    }

    fn jpeg_with_comment_segment(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(&jpeg_segment_bytes(0xFE, payload));
        bytes.extend_from_slice(JPEG_EOI);
        bytes
    }

    fn jpeg_with_after_eoi_payload(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(JPEG_EOI);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn jpeg_segment_bytes(marker: u8, data: &[u8]) -> Vec<u8> {
        let segment_length = data
            .len()
            .checked_add(2)
            .expect("test JPEG segment should fit length field");
        assert!(segment_length <= u16::MAX as usize);

        let mut segment = Vec::new();
        segment.push(0xFF);
        segment.push(marker);
        segment.extend_from_slice(&(segment_length as u16).to_be_bytes());
        segment.extend_from_slice(data);
        segment
    }

    fn png_with_lsb_payload(payload: &[u8], bit_packing: BitPacking) -> Vec<u8> {
        let mut image = image::RgbaImage::from_pixel(32, 32, image::Rgba([0xFE, 0xFE, 0xFE, 0xFF]));
        let bits = payload_bits(payload, bit_packing);
        let mut bit_iter = bits.into_iter();

        for pixel in image.pixels_mut() {
            for channel in &mut pixel.0[..3] {
                if let Some(bit) = bit_iter.next() {
                    *channel = (*channel & 0xFE) | bit;
                }
            }
        }

        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();

        bytes
    }

    fn png_with_rg_2bpp_payload(payload: &[u8], bit_packing: BitPacking) -> Vec<u8> {
        let mut image = image::RgbaImage::from_pixel(32, 32, image::Rgba([0xFE, 0xFE, 0xFE, 0xFF]));
        let bits = payload_bits(payload, bit_packing);
        let mut bit_iter = bits.into_iter();

        for pixel in image.pixels_mut() {
            if let Some(bit) = bit_iter.next() {
                pixel.0[0] = (pixel.0[0] & 0xFE) | bit;
            }

            if let Some(bit) = bit_iter.next() {
                pixel.0[1] = (pixel.0[1] & 0xFE) | bit;
            }
        }

        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();

        bytes
    }

    fn png_with_2x3_matrix_payload(payload: &[u8], bit_packing: BitPacking) -> Vec<u8> {
        let mut image = image::RgbaImage::from_pixel(32, 32, image::Rgba([0xFE, 0xFE, 0xFE, 0xFF]));
        let bits = payload_bits(payload, bit_packing);
        let mut bit_iter = bits.into_iter();

        for pixel in image.pixels_mut() {
            let Some(message_bit_1) = bit_iter.next() else {
                break;
            };
            let message_bit_2 = bit_iter.next().unwrap_or(0);

            // For H = [[1, 1, 0], [0, 1, 1]], choose b1 = 0.
            // Then m1 = b0 xor b1 = b0 and m2 = b1 xor b2 = b2.
            pixel.0[0] = (pixel.0[0] & 0xFE) | message_bit_1;
            pixel.0[1] &= 0xFE;
            pixel.0[2] = (pixel.0[2] & 0xFE) | message_bit_2;
        }

        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();

        bytes
    }

    fn png_with_text_chunk(keyword: &[u8], payload: &[u8]) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(1, 1, image::Rgba([0xFE, 0xFE, 0xFE, 0xFF]));
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();

        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(keyword);
        chunk_data.push(0);
        chunk_data.extend_from_slice(payload);
        let chunk = png_chunk(*b"tEXt", &chunk_data);
        let iend_type_offset = bytes
            .windows(4)
            .position(|window| window == b"IEND")
            .expect("encoded PNG should contain IEND chunk");
        let iend_chunk_offset = iend_type_offset - 4;
        bytes.splice(iend_chunk_offset..iend_chunk_offset, chunk);

        bytes
    }

    fn png_chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend_from_slice(&kind);
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(&png_crc32(&kind, data).to_be_bytes());
        chunk
    }

    fn png_crc32(kind: &[u8; 4], data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF_u32;

        for byte in kind.iter().chain(data.iter()) {
            crc ^= *byte as u32;
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }

        !crc
    }

    fn payload_bits(payload: &[u8], bit_packing: BitPacking) -> Vec<u8> {
        let mut bits = Vec::with_capacity(payload.len() * 8);

        for byte in payload {
            match bit_packing {
                BitPacking::MsbFirst => {
                    for bit_index in (0..8).rev() {
                        bits.push((byte >> bit_index) & 1);
                    }
                }
                BitPacking::LsbFirst => {
                    for bit_index in 0..8 {
                        bits.push((byte >> bit_index) & 1);
                    }
                }
            }
        }

        bits
    }

    fn stegascope_packet(file_name: &str, payload: &[u8]) -> Vec<u8> {
        let name_bytes = file_name.as_bytes();
        let mut packet = Vec::new();
        packet.extend_from_slice(STEGASCOPE_PACKET_MAGIC);
        packet.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        packet.extend_from_slice(Sha256::digest(payload).as_slice());
        packet.extend_from_slice(name_bytes);
        packet.extend_from_slice(payload);
        packet
    }
}
