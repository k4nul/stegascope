use std::borrow::Cow;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::Read;

use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::analyzer_pipeline::{
    assign_payload_ids, dedupe_payloads, outcome_prefer_verified, payloads_prefer_verified,
};
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
        assign_payload_ids(&mut extracted_payloads);
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
pub struct PngContainerAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for PngContainerAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("png-container-analyzer")
                .with_version("0.1.0")
                .with_description(
                    "Scans payload data appended after the structural PNG IEND chunk.",
                ),
        }
    }
}

impl FileAnalyzer for PngContainerAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        Ok(AnalysisOutcome::from_payloads(
            extract_png_container_payloads(media, self.name()),
        ))
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

#[derive(Debug)]
pub struct WavPcmLsbAnalyzer {
    base: BaseFileAnalyzer,
}

impl Default for WavPcmLsbAnalyzer {
    fn default() -> Self {
        Self {
            base: BaseFileAnalyzer::new("wav-pcm-lsb-analyzer")
                .with_version("0.1.0")
                .with_description(
                    "Extracts least-significant-bit streams from PCM WAV sample data.",
                ),
        }
    }
}

impl FileAnalyzer for WavPcmLsbAnalyzer {
    fn base(&self) -> &BaseFileAnalyzer {
        &self.base
    }

    fn analyze(&self, media: &LoadedMedia) -> Result<AnalysisOutcome, AnalysisError> {
        let Some(wav) = wav_pcm_data(&media.bytes) else {
            return Ok(AnalysisOutcome::default());
        };

        let bits = extract_wav_pcm_lsb_bits(wav);
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
                    "wav_pcm_lsb",
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

#[derive(Clone, Copy)]
struct WavPcmData<'a> {
    data: &'a [u8],
    format: WavPcmFormat,
}

#[derive(Clone, Copy)]
struct WavPcmFormat {
    channels: u16,
    bits_per_sample: u16,
    block_align: u16,
}

fn wav_pcm_data(bytes: &[u8]) -> Option<WavPcmData<'_>> {
    if bytes.len() < 12 || !bytes.starts_with(b"RIFF") || &bytes[8..12] != b"WAVE" {
        return None;
    }

    let mut format = None;
    let mut data = None;
    let mut offset = 12;

    while offset.checked_add(8)? <= bytes.len() {
        let chunk_type = &bytes[offset..offset + 4];
        let chunk_size = read_u32_le(bytes, offset + 4)? as usize;
        let data_start = offset.checked_add(8)?;
        let data_end = data_start.checked_add(chunk_size)?;
        if data_end > bytes.len() {
            return None;
        }

        match chunk_type {
            b"fmt " => {
                format = parse_wav_pcm_format(&bytes[data_start..data_end]);
            }
            b"data" if data.is_none() => {
                data = Some(&bytes[data_start..data_end]);
            }
            _ => {}
        }

        if let (Some(format), Some(data)) = (format, data) {
            return Some(WavPcmData { data, format });
        }

        offset = data_end.checked_add(chunk_size % 2)?;
    }

    Some(WavPcmData {
        data: data?,
        format: format?,
    })
}

fn parse_wav_pcm_format(bytes: &[u8]) -> Option<WavPcmFormat> {
    if bytes.len() < 16 {
        return None;
    }

    let audio_format = read_u16_le(bytes, 0)?;
    let channels = read_u16_le(bytes, 2)?;
    let block_align = read_u16_le(bytes, 12)?;
    let bits_per_sample = read_u16_le(bytes, 14)?;
    let bytes_per_sample = usize::from(bits_per_sample.checked_div(8)?);
    let expected_block_align = usize::from(channels).checked_mul(bytes_per_sample)?;

    if audio_format != 1
        || channels == 0
        || !matches!(bits_per_sample, 8 | 16 | 24 | 32)
        || expected_block_align == 0
        || usize::from(block_align) != expected_block_align
    {
        return None;
    }

    Some(WavPcmFormat {
        channels,
        bits_per_sample,
        block_align,
    })
}

fn extract_wav_pcm_lsb_bits(wav: WavPcmData<'_>) -> Vec<u8> {
    let bytes_per_sample = usize::from(wav.format.bits_per_sample / 8);
    let block_align = usize::from(wav.format.block_align);
    let channels = usize::from(wav.format.channels);
    let frame_count = wav.data.len() / block_align;
    let mut bits = Vec::with_capacity(frame_count * channels);

    for frame in wav.data.chunks_exact(block_align) {
        for channel in 0..channels {
            let sample_offset = channel * bytes_per_sample;
            bits.push(frame[sample_offset] & 1);
        }
    }

    bits
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;

    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let slice = bytes.get(offset..end)?;

    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
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
const MAX_DECOMPRESSED_PNG_TEXT_BYTES: usize = 2 * 1024 * 1024;

fn extract_metadata_payloads(media: &LoadedMedia, analyzer_name: &str) -> Vec<ExtractedPayload> {
    if !media.bytes.starts_with(PNG_SIGNATURE) {
        return Vec::new();
    }

    let mut verified_payloads = Vec::new();
    let mut fallback_payloads = Vec::new();

    for chunk in png_metadata_chunks(&media.bytes) {
        let prefix = format!(
            "metadata_png_{}_chunk_{}",
            png_chunk_type_label(chunk.kind),
            chunk.index
        );

        for payload_bytes in png_metadata_payload_views(chunk.kind, chunk.data) {
            let payload_bytes = payload_bytes.as_ref();
            verified_payloads.extend(find_stegascope_packet_candidates(
                payload_bytes,
                analyzer_name,
            ));
            fallback_payloads.extend(signature_payload_candidates(
                payload_bytes,
                None,
                &prefix,
                0,
                SuspiciousLevel::High,
                analyzer_name,
            ));
        }
    }

    payloads_prefer_verified(verified_payloads, fallback_payloads)
}

fn extract_png_container_payloads(
    media: &LoadedMedia,
    analyzer_name: &str,
) -> Vec<ExtractedPayload> {
    if !media.bytes.starts_with(PNG_SIGNATURE) {
        return Vec::new();
    }

    let Some(after_iend) = png_after_iend_payload(&media.bytes) else {
        return Vec::new();
    };

    let verified_payloads = find_stegascope_packet_candidates(after_iend, analyzer_name);
    let fallback_payloads = signature_payload_candidates(
        after_iend,
        None,
        "png_after_iend",
        0,
        SuspiciousLevel::Critical,
        analyzer_name,
    );

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

    while let Some(marker) = next_jpeg_marker(bytes, offset) {
        if marker.marker == 0xD9 || marker.marker == 0xDA {
            break;
        }

        if jpeg_marker_has_no_payload(marker.marker) {
            offset = marker.payload_offset;
            continue;
        }

        let Some((data_start, data_end)) = jpeg_segment_data_bounds(bytes, marker.payload_offset)
        else {
            break;
        };

        index += 1;
        if is_jpeg_payload_segment(marker.marker) {
            segments.push(JpegSegment {
                index,
                marker: marker.marker,
                data: &bytes[data_start..data_end],
            });
        }

        offset = data_end;
    }

    segments
}

fn jpeg_after_eoi_payload(bytes: &[u8]) -> Option<&[u8]> {
    let payload_start = structural_jpeg_eoi_end(bytes)?;

    (payload_start < bytes.len()).then_some(&bytes[payload_start..])
}

#[derive(Clone, Copy)]
struct JpegMarker {
    marker_offset: usize,
    marker: u8,
    payload_offset: usize,
}

fn next_jpeg_marker(bytes: &[u8], mut offset: usize) -> Option<JpegMarker> {
    while offset < bytes.len() {
        if bytes[offset] != 0xFF {
            offset += 1;
            continue;
        }

        let marker_offset = offset;
        while offset < bytes.len() && bytes[offset] == 0xFF {
            offset += 1;
        }

        if offset >= bytes.len() {
            return None;
        }

        let marker = bytes[offset];
        offset += 1;

        if marker == 0x00 {
            continue;
        }

        return Some(JpegMarker {
            marker_offset,
            marker,
            payload_offset: offset,
        });
    }

    None
}

fn jpeg_segment_data_bounds(bytes: &[u8], length_offset: usize) -> Option<(usize, usize)> {
    let length_end = length_offset.checked_add(2)?;
    if length_end > bytes.len() {
        return None;
    }

    let segment_length =
        u16::from_be_bytes([bytes[length_offset], bytes[length_offset + 1]]) as usize;
    if segment_length < 2 {
        return None;
    }

    let data_start = length_end;
    let data_end = data_start.checked_add(segment_length - 2)?;
    if data_end > bytes.len() {
        return None;
    }

    Some((data_start, data_end))
}

fn structural_jpeg_eoi_end(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(JPEG_SOI) {
        return None;
    }

    let mut offset = JPEG_SOI.len();

    while let Some(marker) = next_jpeg_marker(bytes, offset) {
        match marker.marker {
            0xD9 => return Some(marker.payload_offset),
            0xDA => {
                let (_, scan_data_start) = jpeg_segment_data_bounds(bytes, marker.payload_offset)?;
                return jpeg_scan_data_eoi_end(bytes, scan_data_start);
            }
            marker if jpeg_marker_has_no_payload(marker) => {
                offset = marker.payload_offset;
            }
            _ => {
                let (_, data_end) = jpeg_segment_data_bounds(bytes, marker.payload_offset)?;
                offset = data_end;
            }
        }
    }

    None
}

fn jpeg_scan_data_eoi_end(bytes: &[u8], mut offset: usize) -> Option<usize> {
    while offset < bytes.len() {
        if bytes[offset] != 0xFF {
            offset += 1;
            continue;
        }

        while offset < bytes.len() && bytes[offset] == 0xFF {
            offset += 1;
        }

        if offset >= bytes.len() {
            return None;
        }

        let marker = bytes[offset];
        offset += 1;

        match marker {
            0x00 => continue,
            0xD9 => return Some(offset),
            0x01 | 0xD0..=0xD7 => continue,
            0xDA => {
                if let Some((_, scan_data_start)) = jpeg_segment_data_bounds(bytes, offset) {
                    offset = scan_data_start;
                } else {
                    offset = skip_malformed_jpeg_segment_length(bytes, offset);
                }
            }
            marker if jpeg_marker_has_no_payload(marker) => continue,
            _ => {
                if let Some((_, data_end)) = jpeg_segment_data_bounds(bytes, offset) {
                    offset = data_end;
                } else {
                    offset = skip_malformed_jpeg_segment_length(bytes, offset);
                }
            }
        }
    }

    None
}

fn skip_malformed_jpeg_segment_length(bytes: &[u8], length_offset: usize) -> usize {
    length_offset
        .checked_add(2)
        .map(|offset| offset.min(bytes.len()))
        .unwrap_or(bytes.len())
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
        if kind == b"IEND" {
            break;
        }

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

fn png_after_iend_payload(bytes: &[u8]) -> Option<&[u8]> {
    let payload_start = structural_png_iend_end(bytes)?;

    (payload_start < bytes.len()).then_some(&bytes[payload_start..])
}

fn structural_png_iend_end(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(PNG_SIGNATURE) {
        return None;
    }

    let mut offset = PNG_SIGNATURE.len();

    loop {
        let length_end = offset.checked_add(4)?;
        let kind_end = length_end.checked_add(4)?;
        if kind_end > bytes.len() {
            return None;
        }

        let length = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let data_start = kind_end;
        let data_end = data_start.checked_add(length)?;
        let next_offset = data_end.checked_add(4)?;
        if next_offset > bytes.len() {
            return None;
        }

        let kind = &bytes[length_end..kind_end];
        if kind == b"IEND" {
            return (length == 0).then_some(next_offset);
        }

        offset = next_offset;
    }
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

fn png_metadata_payload_views<'a>(kind: &[u8], data: &'a [u8]) -> Vec<Cow<'a, [u8]>> {
    if let Some(text_payload) = png_text_payload_view(kind, data) {
        return vec![text_payload];
    }

    vec![Cow::Borrowed(data)]
}

fn png_text_payload_view<'a>(kind: &[u8], data: &'a [u8]) -> Option<Cow<'a, [u8]>> {
    match kind {
        b"tEXt" => png_text_payload(data).map(Cow::Borrowed),
        b"zTXt" => decoded_ztxt_text(data).map(Cow::Owned),
        b"iTXt" => itxt_text_payload(data),
        _ => None,
    }
}

fn png_text_payload(data: &[u8]) -> Option<&[u8]> {
    let keyword_end = data.iter().position(|byte| *byte == 0)?;
    let text_start = keyword_end.checked_add(1)?;

    (text_start <= data.len()).then_some(&data[text_start..])
}

fn decoded_ztxt_text(data: &[u8]) -> Option<Vec<u8>> {
    let keyword_end = data.iter().position(|byte| *byte == 0)?;
    let compression_method_offset = keyword_end.checked_add(1)?;
    let compressed_text_start = compression_method_offset.checked_add(1)?;

    if compressed_text_start > data.len() || data[compression_method_offset] != 0 {
        return None;
    }

    inflate_zlib_limited(&data[compressed_text_start..])
}

fn itxt_text_payload(data: &[u8]) -> Option<Cow<'_, [u8]>> {
    let keyword_end = data.iter().position(|byte| *byte == 0)?;
    let compression_flag_offset = keyword_end.checked_add(1)?;
    let compression_method_offset = compression_flag_offset.checked_add(1)?;
    let mut offset = compression_method_offset.checked_add(1)?;

    if offset > data.len() {
        return None;
    }

    let compression_flag = data[compression_flag_offset];
    let compression_method = data[compression_method_offset];
    if !matches!(compression_flag, 0 | 1) || compression_method != 0 {
        return None;
    }

    let language_tag_end = data[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .and_then(|position| offset.checked_add(position))?;
    offset = language_tag_end.checked_add(1)?;

    let translated_keyword_end = data[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .and_then(|position| offset.checked_add(position))?;
    let compressed_text_start = translated_keyword_end.checked_add(1)?;

    if compressed_text_start > data.len() {
        return None;
    }

    let text = &data[compressed_text_start..];

    if compression_flag == 0 {
        Some(Cow::Borrowed(text))
    } else {
        inflate_zlib_limited(text).map(Cow::Owned)
    }
}

fn inflate_zlib_limited(compressed: &[u8]) -> Option<Vec<u8>> {
    let decoder = ZlibDecoder::new(compressed);
    let mut limited = decoder.take((MAX_DECOMPRESSED_PNG_TEXT_BYTES + 1) as u64);
    let mut decoded = Vec::new();

    limited.read_to_end(&mut decoded).ok()?;

    if decoded.len() > MAX_DECOMPRESSED_PNG_TEXT_BYTES {
        return None;
    }

    Some(decoded)
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

    use super::super::analyzer_pipeline::extract_payload_candidates;
    use std::io::Write;

    use flate2::{write::ZlibEncoder, Compression};
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
        assert!(file.file_name.ends_with("_payload_0.pdf"));
        assert_eq!(file.analyzer_name, "metadata-analyzer");
        assert_eq!(file.suspicious_level, SuspiciousLevel::High);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn metadata_analyzer_extracts_valid_signature_from_supported_png_metadata_chunk_kinds() {
        let cases = [
            (
                *b"iTXt",
                png_uncompressed_itxt_chunk_data(b"Comment", valid_pdf_payload()),
                "itxt",
            ),
            (*b"eXIf", valid_pdf_payload().to_vec(), "exif"),
        ];

        for (kind, chunk_data, label) in cases {
            let bytes = png_with_chunk(kind, &chunk_data);
            let media = LoadedMedia {
                source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
                bytes,
            };

            let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
            let file = outcome
                .extracted_files
                .iter()
                .find(|file| file.file_type == "application/pdf")
                .expect("expected PDF payload from supported metadata chunk");

            assert!(file
                .file_name
                .starts_with(&format!("metadata_png_{label}_chunk_")));
            assert!(file.file_name.ends_with("_payload_0.pdf"));
            assert_eq!(file.analyzer_name, "metadata-analyzer");
            assert_eq!(file.suspicious_level, SuspiciousLevel::High);
            assert_eq!(file.validation_status, ValidationStatus::Validated);
        }
    }

    #[test]
    fn metadata_analyzer_extracts_valid_signature_from_compressed_png_text_chunks() {
        let cases = [
            (
                *b"zTXt",
                png_ztxt_chunk_data(b"Comment", valid_pdf_payload()),
                "ztxt",
            ),
            (
                *b"iTXt",
                png_compressed_itxt_chunk_data(b"Comment", valid_pdf_payload()),
                "itxt",
            ),
        ];

        for (kind, chunk_data, label) in cases {
            let bytes = png_with_chunk(kind, &chunk_data);
            let media = LoadedMedia {
                source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
                bytes,
            };

            let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
            let file = outcome
                .extracted_files
                .iter()
                .find(|file| file.file_type == "application/pdf")
                .expect("expected compressed PNG text signature payload");

            assert_eq!(
                file.file_name,
                format!("metadata_png_{label}_chunk_1_payload_0.pdf")
            );
            assert_eq!(file.analyzer_name, "metadata-analyzer");
            assert_eq!(file.suspicious_level, SuspiciousLevel::High);
            assert_eq!(file.validation_status, ValidationStatus::Validated);
        }
    }

    #[test]
    fn metadata_analyzer_extracts_packet_payload_from_compressed_png_itxt_chunk() {
        let secret = valid_pdf_payload();
        let packet = stegascope_packet("compressed_itxt_note.pdf", secret);
        let bytes = png_with_chunk(
            *b"iTXt",
            &png_compressed_itxt_chunk_data(b"StegaScope", &packet),
        );
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "compressed_itxt_note.pdf")
            .expect("expected compressed iTXt packet payload");

        assert_eq!(payload.file.analyzer_name, "metadata-analyzer");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn default_pipeline_extracts_packet_payload_from_compressed_png_ztxt_chunk() {
        let secret = valid_pdf_payload();
        let packet = stegascope_packet("compressed_ztxt_note.pdf", secret);
        let bytes = png_with_chunk(*b"zTXt", &png_ztxt_chunk_data(b"StegaScope", &packet));
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let payloads = extract_payload_candidates(&media).unwrap();
        let payload = payloads
            .iter()
            .find(|payload| payload.file.file_name == "compressed_ztxt_note.pdf")
            .expect("expected default pipeline compressed zTXt packet payload");

        assert_eq!(payload.file.analyzer_name, "metadata-analyzer");
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn default_pipeline_extracts_container_side_channel_packets_from_registered_analyzers() {
        let png_secret = b"\x89PNG\r\n\x1A\npipeline-after-iend-blueprint";
        let png_packet = stegascope_packet("pipeline_after_iend.png", png_secret);
        let png_bytes = png_with_after_iend_payload(&png_packet);
        let png_media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", png_bytes.len() as u64, "image/png"),
            bytes: png_bytes,
        };

        let png_payloads = extract_payload_candidates(&png_media).unwrap();

        assert!(png_payloads.iter().any(|payload| {
            payload.file.file_name == "pipeline_after_iend.png"
                && payload.file.analyzer_name == "png-container-analyzer"
                && payload.file.validation_status == ValidationStatus::Verified
                && payload.bytes == png_secret
        }));

        let jpeg_secret = b"\x89PNG\r\n\x1A\npipeline-after-eoi-blueprint";
        let jpeg_packet = stegascope_packet("pipeline_after_eoi.png", jpeg_secret);
        let jpeg_bytes = jpeg_with_after_eoi_payload(&jpeg_packet);
        let jpeg_media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", jpeg_bytes.len() as u64, "image/jpeg"),
            bytes: jpeg_bytes,
        };

        let jpeg_payloads = extract_payload_candidates(&jpeg_media).unwrap();

        assert!(jpeg_payloads.iter().any(|payload| {
            payload.file.file_name == "pipeline_after_eoi.png"
                && payload.file.analyzer_name == "jpeg-segment-analyzer"
                && payload.file.validation_status == ValidationStatus::Verified
                && payload.bytes == jpeg_secret
        }));
    }

    #[test]
    fn metadata_analyzer_extracts_valid_signature_from_custom_ancillary_png_chunk() {
        let bytes = png_with_chunk(*b"stEg", valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
        let file = outcome
            .extracted_files
            .iter()
            .find(|file| {
                file.file_name.starts_with("metadata_png_steg_chunk_")
                    && file.file_name.ends_with("_payload_0.pdf")
            })
            .expect("expected PDF payload from custom ancillary chunk");

        assert_eq!(file.analyzer_name, "metadata-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.suspicious_level, SuspiciousLevel::High);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn metadata_analyzer_ignores_non_metadata_critical_png_chunk() {
        let bytes = png_with_chunk(*b"ABCD", valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
        assert!(outcome.extracted_payloads.is_empty());
    }

    #[test]
    fn metadata_analyzer_handles_truncated_png_chunk_without_extracting() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PNG_SIGNATURE);
        bytes.extend_from_slice(&32_u32.to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(b"Comment\0%PDF");
        let media = LoadedMedia {
            source: MediaFileInfo::new("truncated.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
        assert!(outcome.extracted_payloads.is_empty());
    }

    #[test]
    fn metadata_analyzer_prefers_verified_packet_over_signature_candidates_across_png_chunks() {
        let signature_chunk = png_text_chunk_data(b"Comment", valid_pdf_payload());
        let secret = b"\x89PNG\r\n\x1A\nverified-metadata-payload";
        let packet = stegascope_packet("metadata_blueprint.png", secret);
        let packet_chunk = png_uncompressed_itxt_chunk_data(b"StegaScope", &packet);
        let bytes = png_with_chunks(&[
            (*b"tEXt", signature_chunk.as_slice()),
            (*b"iTXt", packet_chunk.as_slice()),
        ]);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome
            .extracted_payloads
            .iter()
            .all(|payload| payload.source == PayloadSource::VerifiedPacket));
        assert!(outcome.extracted_payloads.iter().any(|payload| {
            payload.file.file_name == "metadata_blueprint.png"
                && payload.file.file_type == "image/png"
                && payload.bytes == secret
        }));
        assert!(!outcome
            .extracted_payloads
            .iter()
            .any(|payload| payload.source == PayloadSource::SignatureScan));
    }

    #[test]
    fn metadata_analyzer_preserves_distinct_packets_with_same_embedded_name() {
        let first_secret = b"%PDF-1.7\nfirst same-name payload\n%%EOF\n";
        let second_secret = b"%PDF-1.7\nsecond same-name payload\n%%EOF\n";
        let first_packet = stegascope_packet("shared_note.pdf", first_secret);
        let second_packet = stegascope_packet("shared_note.pdf", second_secret);
        let first_chunk = png_text_chunk_data(b"Comment", &first_packet);
        let second_chunk = png_text_chunk_data(b"Comment", &second_packet);
        let bytes = png_with_chunks(&[
            (*b"tEXt", first_chunk.as_slice()),
            (*b"tEXt", second_chunk.as_slice()),
        ]);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();
        let shared_payloads = outcome
            .extracted_payloads
            .iter()
            .filter(|payload| payload.file.file_name == "shared_note.pdf")
            .collect::<Vec<_>>();

        assert_eq!(shared_payloads.len(), 2);
        assert!(shared_payloads
            .iter()
            .all(|payload| payload.source == PayloadSource::VerifiedPacket));
        assert!(shared_payloads
            .iter()
            .any(|payload| payload.bytes == first_secret));
        assert!(shared_payloads
            .iter()
            .any(|payload| payload.bytes == second_secret));

        let shared_files = outcome
            .extracted_files
            .iter()
            .filter(|file| file.file_name == "shared_note.pdf")
            .collect::<Vec<_>>();
        assert_eq!(shared_files.len(), 2);
        assert_ne!(shared_files[0].id, shared_files[1].id);
        assert!(shared_files
            .iter()
            .all(|file| file.id.starts_with("payload-")));
    }

    #[test]
    fn metadata_analyzer_does_not_scan_chunks_after_iend() {
        let chunk_data = png_text_chunk_data(b"Comment", valid_pdf_payload());
        let mut bytes = png_with_chunks(&[]);
        bytes.extend_from_slice(&png_chunk(*b"tEXt", &chunk_data));
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = MetadataAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
        assert!(outcome.extracted_payloads.is_empty());
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
    fn png_container_analyzer_extracts_packet_payload_after_iend() {
        let secret = valid_pdf_payload();
        let packet = stegascope_packet("png_container_note.pdf", secret);
        let bytes = png_with_after_iend_payload(&packet);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = PngContainerAnalyzer::default().analyze(&media).unwrap();
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "png_container_note.pdf")
            .expect("expected after-IEND packet payload");

        assert_eq!(payload.file.analyzer_name, "png-container-analyzer");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.file_size_bytes, secret.len() as u64);
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn png_container_analyzer_prefers_verified_packet_after_iend_over_signature_candidates() {
        let secret = b"\x89PNG\r\n\x1A\nverified-after-iend-blueprint";
        let packet = stegascope_packet("after_iend_blueprint.png", secret);
        let mut after_iend = valid_pdf_payload().to_vec();
        after_iend.extend_from_slice(&packet);
        let bytes = png_with_after_iend_payload(&after_iend);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = PngContainerAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome
            .extracted_payloads
            .iter()
            .all(|payload| payload.source == PayloadSource::VerifiedPacket));
        assert!(outcome.extracted_payloads.iter().any(|payload| {
            payload.file.file_name == "after_iend_blueprint.png"
                && payload.file.file_type == "image/png"
                && payload.file.analyzer_name == "png-container-analyzer"
                && payload.file.validation_status == ValidationStatus::Verified
                && payload.bytes == secret
        }));
        assert!(!outcome
            .extracted_payloads
            .iter()
            .any(|payload| payload.source == PayloadSource::SignatureScan));
    }

    #[test]
    fn png_container_analyzer_rejects_invalid_packet_and_keeps_signature_fallback() {
        let mut invalid_packet = stegascope_packet("corrupt_packet.pdf", valid_pdf_payload());
        invalid_packet[18] ^= 0xFF;
        let bytes = png_with_after_iend_payload(&invalid_packet);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = PngContainerAnalyzer::default().analyze(&media).unwrap();

        assert!(!outcome
            .extracted_payloads
            .iter()
            .any(|payload| payload.source == PayloadSource::VerifiedPacket));
        assert!(outcome.extracted_payloads.iter().any(|payload| {
            payload.source == PayloadSource::SignatureScan
                && payload.file.file_type == "application/pdf"
                && payload.bytes == valid_pdf_payload()
        }));
    }

    #[test]
    fn png_container_analyzer_extracts_valid_signature_after_iend() {
        let bytes = png_with_after_iend_payload(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = PngContainerAnalyzer::default().analyze(&media).unwrap();
        let file = outcome
            .extracted_files
            .iter()
            .find(|file| file.file_name == "png_after_iend_payload_0.pdf")
            .expect("expected after-IEND PDF payload");

        assert_eq!(file.analyzer_name, "png-container-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn png_container_analyzer_uses_structural_iend_for_trailing_payload() {
        let mut metadata_note = b"note-IEND-inside-metadata".to_vec();
        metadata_note.extend_from_slice(valid_pdf_payload());
        let mut bytes = png_with_text_chunk(b"Comment", &metadata_note);
        bytes.extend_from_slice(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = PngContainerAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "png_after_iend_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
                && file.validation_status == ValidationStatus::Validated
        }));
        assert_eq!(outcome.extracted_files.len(), 1);
    }

    #[test]
    fn png_container_analyzer_handles_truncated_png_without_extracting() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PNG_SIGNATURE);
        bytes.extend_from_slice(&32_u32.to_be_bytes());
        bytes.extend_from_slice(b"tEXt");
        bytes.extend_from_slice(b"Comment\0%PDF");
        let media = LoadedMedia {
            source: MediaFileInfo::new("truncated.png", bytes.len() as u64, "image/png"),
            bytes,
        };

        let outcome = PngContainerAnalyzer::default().analyze(&media).unwrap();

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
    fn jpeg_segment_analyzer_prefers_verified_after_eoi_packet_over_segment_signature_candidates() {
        let secret = b"\x89PNG\r\n\x1A\nverified-after-eoi-blueprint";
        let packet = stegascope_packet("after_eoi_blueprint.png", secret);
        let bytes = jpeg_with_comment_segment_and_after_eoi_payload(valid_pdf_payload(), &packet);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome
            .extracted_payloads
            .iter()
            .all(|payload| payload.source == PayloadSource::VerifiedPacket));
        assert!(outcome.extracted_payloads.iter().any(|payload| {
            payload.file.file_name == "after_eoi_blueprint.png"
                && payload.file.file_type == "image/png"
                && payload.file.analyzer_name == "jpeg-segment-analyzer"
                && payload.file.validation_status == ValidationStatus::Verified
                && payload.bytes == secret
        }));
        assert!(!outcome
            .extracted_payloads
            .iter()
            .any(|payload| payload.source == PayloadSource::SignatureScan));
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
    fn jpeg_segment_analyzer_labels_post_eoi_data_as_after_eoi_not_segment() {
        let post_eoi_segment = jpeg_segment_bytes(0xE1, valid_pdf_payload());
        let bytes = jpeg_with_after_eoi_payload(&post_eoi_segment);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "jpeg_after_eoi_payload_4.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
                && file.validation_status == ValidationStatus::Validated
        }));
        assert!(!outcome
            .extracted_files
            .iter()
            .any(|file| file.file_name.starts_with("jpeg_app")));
    }

    #[test]
    fn jpeg_segment_analyzer_extracts_valid_signature_from_app_segment() {
        let bytes = jpeg_with_segment_and_eoi(0xE1, valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();
        let file = outcome
            .extracted_files
            .iter()
            .find(|file| file.file_name == "jpeg_app1_segment_1_payload_0.pdf")
            .expect("expected APP1 PDF payload");

        assert_eq!(file.analyzer_name, "jpeg-segment-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.suspicious_level, SuspiciousLevel::High);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn jpeg_segment_analyzer_uses_structural_eoi_for_trailing_payload() {
        let bytes = jpeg_with_comment_segment_and_after_eoi_payload(
            b"segment-note\xFF\xD9inside-comment",
            valid_pdf_payload(),
        );
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "jpeg_after_eoi_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
                && file.validation_status == ValidationStatus::Validated
        }));
        assert!(!outcome.extracted_files.iter().any(|file| {
            file.file_name.starts_with("jpeg_after_eoi_payload_")
                && file.file_name != "jpeg_after_eoi_payload_0.pdf"
        }));
    }

    #[test]
    fn jpeg_segment_analyzer_does_not_treat_comment_data_after_false_eoi_as_trailing_payload() {
        let mut comment = b"comment-prefix\xFF\xD9".to_vec();
        comment.extend_from_slice(valid_pdf_payload());
        let bytes = jpeg_with_comment_segment(&comment);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name.starts_with("jpeg_com_segment_1_payload_")
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::High
        }));
        assert!(!outcome
            .extracted_files
            .iter()
            .any(|file| file.file_name.starts_with("jpeg_after_eoi_payload_")));
    }

    #[test]
    fn jpeg_segment_analyzer_does_not_scan_sos_image_data_as_segment_payload() {
        let bytes = jpeg_with_sos_scan_data(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
        assert!(outcome.extracted_payloads.is_empty());
    }

    #[test]
    fn jpeg_segment_analyzer_ignores_marker_shaped_sos_image_data() {
        let marker_shaped_scan_data = jpeg_segment_bytes(0xE1, valid_pdf_payload());
        let bytes = jpeg_with_sos_scan_data(&marker_shaped_scan_data);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert!(outcome.extracted_files.is_empty());
        assert!(outcome.extracted_payloads.is_empty());
    }

    #[test]
    fn jpeg_segment_analyzer_ignores_byte_stuffed_eoi_in_sos_scan_data() {
        let scan_payload = b"%PDF-1.7\nscan data decoy\n%%EOF\n";
        let after_eoi_payload = valid_pdf_payload();
        let mut scan_data = b"scan data before byte-stuffed marker".to_vec();
        scan_data.extend_from_slice(&[0xFF, 0x00, 0xD9]);
        scan_data.extend_from_slice(scan_payload);
        let mut bytes = jpeg_with_sos_scan_data(&scan_data);
        bytes.extend_from_slice(after_eoi_payload);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert_eq!(outcome.extracted_files.len(), 1);
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "jpeg_after_eoi_payload_0.pdf")
            .expect("expected after-EOI payload");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Validated);
        assert_eq!(payload.bytes, after_eoi_payload);
        assert!(!outcome
            .extracted_payloads
            .iter()
            .any(|payload| payload.bytes == scan_payload));
    }

    #[test]
    fn jpeg_segment_analyzer_ignores_restart_and_fill_markers_in_sos_scan_data() {
        let scan_payload = b"%PDF-1.7\nrestart marker decoy\n%%EOF\n";
        let after_eoi_payload = valid_pdf_payload();
        let mut scan_data = b"scan data before restart marker".to_vec();
        scan_data.extend_from_slice(&[0xFF, 0xFF, 0xD3]);
        scan_data.extend_from_slice(&[0xFF, 0x01]);
        scan_data.extend_from_slice(scan_payload);
        let mut bytes = jpeg_with_sos_scan_data(&scan_data);
        bytes.extend_from_slice(after_eoi_payload);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert_eq!(outcome.extracted_files.len(), 1);
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "jpeg_after_eoi_payload_0.pdf")
            .expect("expected after-EOI payload");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Validated);
        assert_eq!(payload.bytes, after_eoi_payload);
        assert!(!outcome
            .extracted_payloads
            .iter()
            .any(|payload| payload.bytes == scan_payload));
    }

    #[test]
    fn jpeg_segment_analyzer_recovers_after_malformed_sos_marker_shaped_data() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(&jpeg_segment_bytes(0xDA, b"\x01\x01\x00"));
        bytes.extend_from_slice(b"scan data before false marker");
        bytes.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x00]);
        bytes.extend_from_slice(b"scan data after false marker");
        bytes.extend_from_slice(JPEG_EOI);
        bytes.extend_from_slice(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert_eq!(outcome.extracted_files.len(), 1);
        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "jpeg_after_eoi_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
                && file.validation_status == ValidationStatus::Validated
        }));
        assert!(!outcome
            .extracted_files
            .iter()
            .any(|file| file.file_name.starts_with("jpeg_app")));
    }

    #[test]
    fn jpeg_segment_analyzer_ignores_false_eoi_in_malformed_sos_marker_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(&jpeg_segment_bytes(0xDA, b"\x01\x01\x00"));
        bytes.extend_from_slice(b"scan data before malformed marker");
        bytes.extend_from_slice(&[0xFF, 0xE1, 0xFF, 0xD9]);
        bytes.extend_from_slice(b"scan data after false eoi length bytes");
        bytes.extend_from_slice(JPEG_EOI);
        bytes.extend_from_slice(valid_pdf_payload());
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert_eq!(outcome.extracted_files.len(), 1);
        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "jpeg_after_eoi_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
                && file.validation_status == ValidationStatus::Validated
        }));
        assert!(!outcome
            .extracted_files
            .iter()
            .any(|file| file.file_name.starts_with("jpeg_app")));
    }

    #[test]
    fn jpeg_segment_analyzer_skips_post_sos_segment_payload_when_finding_after_eoi() {
        let post_scan_segment_payload = b"segment payload with false eoi \xFF\xD9";
        let bytes = jpeg_with_post_sos_segment_and_after_eoi_payload(
            0xE1,
            post_scan_segment_payload,
            valid_pdf_payload(),
        );
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
            bytes,
        };

        let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

        assert_eq!(outcome.extracted_files.len(), 1);
        assert!(outcome.extracted_files.iter().any(|file| {
            file.file_name == "jpeg_after_eoi_payload_0.pdf"
                && file.file_type == "application/pdf"
                && file.suspicious_level == SuspiciousLevel::Critical
                && file.validation_status == ValidationStatus::Validated
        }));
        assert!(!outcome
            .extracted_files
            .iter()
            .any(|file| file.file_name.starts_with("jpeg_app")));
    }

    #[test]
    fn jpeg_segment_analyzer_handles_malformed_segment_lengths() {
        let malformed_inputs = [
            vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x01, b'%', b'P', b'D', b'F'],
            vec![0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x20, b'%', b'P', b'D', b'F'],
        ];

        for bytes in malformed_inputs {
            let media = LoadedMedia {
                source: MediaFileInfo::new("carrier.jpg", bytes.len() as u64, "image/jpeg"),
                bytes,
            };

            let outcome = JpegSegmentAnalyzer::default().analyze(&media).unwrap();

            assert!(outcome.extracted_files.is_empty());
            assert!(outcome.extracted_payloads.is_empty());
        }
    }

    #[test]
    fn wav_pcm_lsb_analyzer_extracts_packet_payload_from_16_bit_samples() {
        let secret = valid_pdf_payload();
        let packet = stegascope_packet("wav_lsb_note.pdf", secret);
        let bytes = wav_pcm_with_lsb_payload(&packet, BitPacking::MsbFirst, 16);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.wav", bytes.len() as u64, "audio/wav"),
            bytes,
        };

        let outcome = WavPcmLsbAnalyzer::default().analyze(&media).unwrap();
        let payload = outcome
            .extracted_payloads
            .iter()
            .find(|payload| payload.file.file_name == "wav_lsb_note.pdf")
            .expect("expected WAV PCM LSB packet payload");

        assert_eq!(payload.file.analyzer_name, "wav-pcm-lsb-analyzer");
        assert_eq!(payload.file.file_type, "application/pdf");
        assert_eq!(payload.file.file_size_bytes, secret.len() as u64);
        assert_eq!(payload.file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn wav_pcm_lsb_analyzer_extracts_valid_signature_from_8_bit_samples() {
        let bytes = wav_pcm_with_lsb_payload(valid_pdf_payload(), BitPacking::MsbFirst, 8);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.wav", bytes.len() as u64, "audio/wav"),
            bytes,
        };

        let outcome = WavPcmLsbAnalyzer::default().analyze(&media).unwrap();
        let file = outcome
            .extracted_files
            .iter()
            .find(|file| file.file_name == "wav_pcm_lsb_msb_first_payload_0.pdf")
            .expect("expected WAV PCM LSB PDF payload");

        assert_eq!(file.analyzer_name, "wav-pcm-lsb-analyzer");
        assert_eq!(file.file_type, "application/pdf");
        assert_eq!(file.suspicious_level, SuspiciousLevel::Critical);
        assert_eq!(file.validation_status, ValidationStatus::Validated);
    }

    #[test]
    fn default_pipeline_extracts_packet_payload_from_wav_pcm_lsb() {
        let secret = b"\x89PNG\r\n\x1A\nwav-lsb-blueprint";
        let packet = stegascope_packet("wav_blueprint.png", secret);
        let bytes = wav_pcm_with_lsb_payload(&packet, BitPacking::LsbFirst, 24);
        let media = LoadedMedia {
            source: MediaFileInfo::new("carrier.wav", bytes.len() as u64, "audio/wav"),
            bytes,
        };

        let payloads = extract_payload_candidates(&media).unwrap();
        let payload = payloads
            .iter()
            .find(|payload| payload.file.file_name == "wav_blueprint.png")
            .expect("expected default pipeline WAV PCM LSB packet payload");

        assert_eq!(payload.file.analyzer_name, "wav-pcm-lsb-analyzer");
        assert_eq!(payload.file.validation_status, ValidationStatus::Verified);
        assert_eq!(payload.bytes, secret);
    }

    #[test]
    fn wav_pcm_lsb_analyzer_ignores_unsupported_or_truncated_wav() {
        let unsupported_float = wav_bytes(3, 1, 32, vec![0; 32]);
        let mut truncated = wav_pcm_with_lsb_payload(valid_pdf_payload(), BitPacking::MsbFirst, 16);
        truncated.truncate(truncated.len() - 3);

        for bytes in [unsupported_float, truncated] {
            let media = LoadedMedia {
                source: MediaFileInfo::new("carrier.wav", bytes.len() as u64, "audio/wav"),
                bytes,
            };

            let outcome = WavPcmLsbAnalyzer::default().analyze(&media).unwrap();

            assert!(outcome.extracted_files.is_empty());
            assert!(outcome.extracted_payloads.is_empty());
        }
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
        jpeg_with_segment_and_eoi(0xFE, payload)
    }

    fn jpeg_with_segment_and_eoi(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(&jpeg_segment_bytes(marker, payload));
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

    fn jpeg_with_comment_segment_and_after_eoi_payload(comment: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = jpeg_with_comment_segment(comment);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn jpeg_with_sos_scan_data(scan_data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(&jpeg_segment_bytes(0xDA, b"\x01\x01\x00"));
        bytes.extend_from_slice(scan_data);
        bytes.extend_from_slice(JPEG_EOI);
        bytes
    }

    fn jpeg_with_post_sos_segment_and_after_eoi_payload(
        marker: u8,
        segment_payload: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(JPEG_SOI);
        bytes.extend_from_slice(&jpeg_segment_bytes(0xDA, b"\x01\x01\x00"));
        bytes.extend_from_slice(b"first scan");
        bytes.extend_from_slice(&jpeg_segment_bytes(marker, segment_payload));
        bytes.extend_from_slice(&jpeg_segment_bytes(0xDA, b"\x01\x01\x00"));
        bytes.extend_from_slice(b"second scan");
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

    fn wav_pcm_with_lsb_payload(
        payload: &[u8],
        bit_packing: BitPacking,
        bits_per_sample: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        for bit in payload_bits(payload, bit_packing) {
            match bits_per_sample {
                8 => data.push(0x80 | bit),
                16 => data.extend_from_slice(&(bit as i16).to_le_bytes()),
                24 => data.extend_from_slice(&[bit, 0, 0]),
                32 => data.extend_from_slice(&(bit as i32).to_le_bytes()),
                _ => panic!("unsupported test PCM width"),
            }
        }

        wav_bytes(1, 1, bits_per_sample, data)
    }

    fn wav_bytes(audio_format: u16, channels: u16, bits_per_sample: u16, data: Vec<u8>) -> Vec<u8> {
        let sample_rate = 8_000_u32;
        let bytes_per_sample = u32::from(bits_per_sample / 8);
        let block_align = channels * (bits_per_sample / 8);
        let byte_rate = sample_rate * u32::from(channels) * bytes_per_sample;
        let mut format = Vec::new();
        format.extend_from_slice(&audio_format.to_le_bytes());
        format.extend_from_slice(&channels.to_le_bytes());
        format.extend_from_slice(&sample_rate.to_le_bytes());
        format.extend_from_slice(&byte_rate.to_le_bytes());
        format.extend_from_slice(&block_align.to_le_bytes());
        format.extend_from_slice(&bits_per_sample.to_le_bytes());

        let mut chunks = Vec::new();
        chunks.extend_from_slice(&wav_chunk(*b"fmt ", &format));
        chunks.extend_from_slice(&wav_chunk(*b"data", &data));

        let riff_size = 4_u32 + chunks.len() as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&riff_size.to_le_bytes());
        bytes.extend_from_slice(b"WAVE");
        bytes.extend_from_slice(&chunks);

        bytes
    }

    fn wav_chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&kind);
        chunk.extend_from_slice(&(data.len() as u32).to_le_bytes());
        chunk.extend_from_slice(data);

        if data.len() % 2 == 1 {
            chunk.push(0);
        }

        chunk
    }

    fn png_with_text_chunk(keyword: &[u8], payload: &[u8]) -> Vec<u8> {
        let chunk_data = png_text_chunk_data(keyword, payload);
        png_with_chunk(*b"tEXt", &chunk_data)
    }

    fn png_text_chunk_data(keyword: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(keyword);
        chunk_data.push(0);
        chunk_data.extend_from_slice(payload);
        chunk_data
    }

    fn png_ztxt_chunk_data(keyword: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(keyword);
        chunk_data.push(0);
        chunk_data.push(0);
        chunk_data.extend_from_slice(&zlib_compress(payload));
        chunk_data
    }

    fn png_uncompressed_itxt_chunk_data(keyword: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(keyword);
        chunk_data.push(0);
        chunk_data.push(0);
        chunk_data.push(0);
        chunk_data.extend_from_slice(b"en");
        chunk_data.push(0);
        chunk_data.extend_from_slice(b"Comment");
        chunk_data.push(0);
        chunk_data.extend_from_slice(payload);
        chunk_data
    }

    fn png_compressed_itxt_chunk_data(keyword: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(keyword);
        chunk_data.push(0);
        chunk_data.push(1);
        chunk_data.push(0);
        chunk_data.extend_from_slice(b"en");
        chunk_data.push(0);
        chunk_data.extend_from_slice(b"Comment");
        chunk_data.push(0);
        chunk_data.extend_from_slice(&zlib_compress(payload));
        chunk_data
    }

    fn zlib_compress(payload: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn png_with_chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        png_with_chunks(&[(kind, data)])
    }

    fn png_with_chunks(chunks: &[([u8; 4], &[u8])]) -> Vec<u8> {
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

        let mut inserted_chunks = Vec::new();
        for (kind, data) in chunks {
            inserted_chunks.extend_from_slice(&png_chunk(*kind, data));
        }
        let iend_type_offset = bytes
            .windows(4)
            .position(|window| window == b"IEND")
            .expect("encoded PNG should contain IEND chunk");
        let iend_chunk_offset = iend_type_offset - 4;
        bytes.splice(iend_chunk_offset..iend_chunk_offset, inserted_chunks);

        bytes
    }

    fn png_with_after_iend_payload(payload: &[u8]) -> Vec<u8> {
        let mut bytes = png_with_chunks(&[]);
        bytes.extend_from_slice(payload);
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
