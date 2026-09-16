// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The Lance Authors

use crate::{
    format::pb,
    rowids::{bitmap::Bitmap, runs::HoleRuns},
};
use lance_core::{Error, Result};

use super::{RowIdSequence, U64Segment, encoded_array::EncodedU64Array};
use bytes::Buf;
use prost::Message;

const ROW_ID_METADATA: &str = "row ID metadata";

pub(super) fn corrupt_row_id_metadata(message: impl Into<String>) -> Error {
    Error::corrupt_file_named(ROW_ID_METADATA, message)
}

fn validate_range(segment_type: &str, start: u64, end: u64) -> Result<usize> {
    let len = end.checked_sub(start).ok_or_else(|| {
        corrupt_row_id_metadata(format!(
            "{segment_type} range start {start} exceeds end {end}"
        ))
    })?;
    usize::try_from(len).map_err(|_| {
        corrupt_row_id_metadata(format!(
            "{segment_type} range length {len} for start {start} and end {end} exceeds usize::MAX"
        ))
    })
}

fn validate_packed_array_length(array_type: &str, byte_len: usize, width: usize) -> Result<()> {
    if !byte_len.is_multiple_of(width) {
        return Err(corrupt_row_id_metadata(format!(
            "encoded {array_type} array byte length {byte_len} is not a multiple of element width {width}"
        )));
    }
    Ok(())
}

fn first_descending_pair(array: &EncodedU64Array) -> Option<(usize, u64, u64)> {
    match array {
        EncodedU64Array::U16 { offsets, .. } => offsets
            .windows(2)
            .position(|pair| pair[0] > pair[1])
            .map(|index| (index, offsets[index] as u64, offsets[index + 1] as u64)),
        EncodedU64Array::U32 { offsets, .. } => offsets
            .windows(2)
            .position(|pair| pair[0] > pair[1])
            .map(|index| (index, offsets[index] as u64, offsets[index + 1] as u64)),
        EncodedU64Array::U64(values) => values
            .windows(2)
            .position(|pair| pair[0] > pair[1])
            .map(|index| (index, values[index], values[index + 1])),
    }
}

fn first_non_increasing_pair(array: &EncodedU64Array) -> Option<(usize, u64, u64)> {
    let mut values = array.iter();
    let previous = values.next()?;
    values
        .scan(previous, |previous, value| {
            let pair = (*previous, value);
            *previous = value;
            Some(pair)
        })
        .enumerate()
        .find_map(|(index, (previous, next))| (previous >= next).then_some((index, previous, next)))
}

/// The offsets of a `RangeWithRuns` array as `u32`, rejecting any that do not
/// fit. Works on the concrete encoding rather than through
/// `EncodedU64Array::iter`, whose boxed iterator costs a virtual call per
/// offset; a compacted table decodes tens of millions of them at open.
fn run_offsets(name: &str, array: EncodedU64Array) -> Result<Vec<u32>> {
    let too_wide = |offset: u64| {
        corrupt_row_id_metadata(format!(
            "RangeWithRuns {name} offset {offset} exceeds u32::MAX"
        ))
    };
    match array {
        EncodedU64Array::U32 { base: 0, offsets } => Ok(offsets),
        EncodedU64Array::U32 { base, offsets } => offsets
            .into_iter()
            .map(|offset| {
                let offset = base + offset as u64;
                u32::try_from(offset).map_err(|_| too_wide(offset))
            })
            .collect(),
        EncodedU64Array::U16 { base, offsets } => offsets
            .into_iter()
            .map(|offset| {
                let offset = base + offset as u64;
                u32::try_from(offset).map_err(|_| too_wide(offset))
            })
            .collect(),
        EncodedU64Array::U64(values) => values
            .into_iter()
            .map(|offset| u32::try_from(offset).map_err(|_| too_wide(offset)))
            .collect(),
    }
}

impl TryFrom<pb::RowIdSequence> for RowIdSequence {
    type Error = Error;

    fn try_from(pb: pb::RowIdSequence) -> Result<Self> {
        let segments = pb
            .segments
            .into_iter()
            .map(U64Segment::try_from)
            .collect::<Result<Vec<_>>>()?;
        // Each segment length fits a usize on its own, but the total need not fit a u64.
        // Reject that here so `RowIdSequence::len()` stays total for anything decoded.
        segments
            .iter()
            .try_fold(0_u64, |total, segment| {
                total.checked_add(segment.len() as u64)
            })
            .ok_or_else(|| {
                corrupt_row_id_metadata(format!(
                    "row ID sequence of {} segments has a total length exceeding u64::MAX",
                    segments.len()
                ))
            })?;
        Ok(Self(segments))
    }
}

impl TryFrom<pb::U64Segment> for U64Segment {
    type Error = Error;

    fn try_from(pb: pb::U64Segment) -> Result<Self> {
        use pb::u64_segment as pb_seg;
        use pb::u64_segment::Segment::*;
        match pb.segment {
            Some(Range(pb_seg::Range { start, end })) => {
                validate_range("Range", start, end)?;
                Ok(Self::Range(start..end))
            }
            Some(RangeWithHoles(pb_seg::RangeWithHoles { start, end, holes })) => {
                validate_range("RangeWithHoles", start, end)?;
                let holes = holes
                    .ok_or_else(|| {
                        corrupt_row_id_metadata("RangeWithHoles is missing its holes array")
                    })?
                    .try_into()?;
                if let Some((index, previous, next)) = first_non_increasing_pair(&holes) {
                    return Err(corrupt_row_id_metadata(format!(
                        "RangeWithHoles values are not strictly increasing at indices {index} and {}: {previous} is not less than {next}",
                        index + 1
                    )));
                }
                if let Some(hole) = holes.iter().find(|hole| *hole < start || *hole >= end) {
                    return Err(corrupt_row_id_metadata(format!(
                        "RangeWithHoles hole {hole} is outside the range {start}..{end}"
                    )));
                }
                Ok(Self::RangeWithHoles {
                    range: start..end,
                    holes,
                })
            }
            Some(RangeWithRuns(pb_seg::RangeWithRuns {
                start,
                end,
                hole_starts,
                hole_ends,
            })) => {
                let range_len = validate_range("RangeWithRuns", start, end)?;
                let span = u32::try_from(range_len).map_err(|_| {
                    corrupt_row_id_metadata(format!(
                        "RangeWithRuns span {range_len} for start {start} and end {end} exceeds u32::MAX"
                    ))
                })?;
                let decode_offsets = |name: &str, array: Option<pb::EncodedU64Array>| {
                    let array: EncodedU64Array = array
                        .ok_or_else(|| {
                            corrupt_row_id_metadata(format!(
                                "RangeWithRuns is missing its {name} array"
                            ))
                        })?
                        .try_into()?;
                    run_offsets(name, array)
                };
                let runs = HoleRuns::try_new(
                    span,
                    decode_offsets("hole_starts", hole_starts)?,
                    decode_offsets("hole_ends", hole_ends)?,
                )?;
                Ok(Self::RangeWithRuns {
                    range: start..end,
                    runs,
                })
            }
            Some(RangeWithBitmap(pb_seg::RangeWithBitmap { start, end, bitmap })) => {
                let range_len = validate_range("RangeWithBitmap", start, end)?;
                let expected_bitmap_len = range_len.div_ceil(8);
                if bitmap.len() != expected_bitmap_len {
                    return Err(corrupt_row_id_metadata(format!(
                        "RangeWithBitmap byte length {} does not match expected {expected_bitmap_len} for range start {start}, end {end}, and length {range_len}",
                        bitmap.len()
                    )));
                }
                let remainder = range_len % 8;
                if remainder != 0 {
                    let padding_mask = !((1_u8 << remainder) - 1);
                    let last_byte = bitmap[expected_bitmap_len - 1];
                    if last_byte & padding_mask != 0 {
                        return Err(corrupt_row_id_metadata(format!(
                            "RangeWithBitmap padding bits must be zero for range start {start}, end {end}, and length {range_len}: last byte {last_byte:#04x} has padding mask {padding_mask:#04x} set"
                        )));
                    }
                }
                Ok(Self::RangeWithBitmap {
                    range: start..end,
                    bitmap: Bitmap::from_parts(bitmap, range_len),
                })
            }
            Some(SortedArray(array)) => {
                let array = EncodedU64Array::try_from(array)?;
                if let Some((index, previous, next)) = first_descending_pair(&array) {
                    return Err(corrupt_row_id_metadata(format!(
                        "SortedArray values are not sorted at indices {index} and {}: {previous} exceeds {next}",
                        index + 1
                    )));
                }
                Ok(Self::SortedArray(array))
            }
            Some(Array(array)) => Ok(Self::Array(EncodedU64Array::try_from(array)?)),
            // TODO: why non-exhaustive?
            // Some(_) => Err(Error::invalid_input("unknown segment type")),
            None => Err(corrupt_row_id_metadata("missing row ID segment type")),
        }
    }
}

impl TryFrom<pb::EncodedU64Array> for EncodedU64Array {
    type Error = Error;

    fn try_from(pb: pb::EncodedU64Array) -> Result<Self> {
        use pb::encoded_u64_array as pb_arr;
        use pb::encoded_u64_array::Array::*;
        match pb.array {
            Some(U16Array(pb_arr::U16Array { base, offsets })) => {
                validate_packed_array_length("u16", offsets.len(), 2)?;
                let offsets = offsets
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>();
                if let Some(max_offset) = offsets.iter().copied().max()
                    && base.checked_add(u64::from(max_offset)).is_none()
                {
                    return Err(corrupt_row_id_metadata(format!(
                        "U16Array base {base} plus maximum offset {max_offset} overflows u64"
                    )));
                }
                Ok(Self::U16 { base, offsets })
            }
            Some(U32Array(pb_arr::U32Array { base, offsets })) => {
                validate_packed_array_length("u32", offsets.len(), 4)?;
                let offsets = offsets
                    .chunks_exact(4)
                    .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect::<Vec<_>>();
                if let Some(max_offset) = offsets.iter().copied().max()
                    && base.checked_add(u64::from(max_offset)).is_none()
                {
                    return Err(corrupt_row_id_metadata(format!(
                        "U32Array base {base} plus maximum offset {max_offset} overflows u64"
                    )));
                }
                Ok(Self::U32 { base, offsets })
            }
            Some(U64Array(pb_arr::U64Array { values })) => {
                validate_packed_array_length("u64", values.len(), 8)?;
                let values = values
                    .chunks_exact(8)
                    .map(|chunk| {
                        u64::from_le_bytes([
                            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                            chunk[7],
                        ])
                    })
                    .collect();
                Ok(Self::U64(values))
            }
            // TODO: shouldn't this enum be non-exhaustive?
            // Some(_) => Err(Error::invalid_input("unknown array type")),
            None => Err(corrupt_row_id_metadata("missing encoded row ID array type")),
        }
    }
}

impl From<RowIdSequence> for pb::RowIdSequence {
    fn from(sequence: RowIdSequence) -> Self {
        Self {
            segments: sequence.0.into_iter().map(pb::U64Segment::from).collect(),
        }
    }
}

impl From<U64Segment> for pb::U64Segment {
    fn from(segment: U64Segment) -> Self {
        match segment {
            U64Segment::Range(range) => Self {
                segment: Some(pb::u64_segment::Segment::Range(pb::u64_segment::Range {
                    start: range.start,
                    end: range.end,
                })),
            },
            U64Segment::RangeWithHoles { range, holes } => Self {
                segment: Some(pb::u64_segment::Segment::RangeWithHoles(
                    pb::u64_segment::RangeWithHoles {
                        start: range.start,
                        end: range.end,
                        holes: Some(holes.into()),
                    },
                )),
            },
            U64Segment::RangeWithBitmap { range, bitmap } => Self {
                segment: Some(pb::u64_segment::Segment::RangeWithBitmap(
                    pb::u64_segment::RangeWithBitmap {
                        start: range.start,
                        end: range.end,
                        bitmap: bitmap.into_bytes(),
                    },
                )),
            },
            U64Segment::RangeWithRuns { range, runs } => {
                let offsets = |values: &[u32]| {
                    Some(
                        EncodedU64Array::from(values.iter().map(|&v| v as u64).collect::<Vec<_>>())
                            .into(),
                    )
                };
                Self {
                    segment: Some(pb::u64_segment::Segment::RangeWithRuns(
                        pb::u64_segment::RangeWithRuns {
                            start: range.start,
                            end: range.end,
                            hole_starts: offsets(runs.starts()),
                            hole_ends: offsets(runs.ends()),
                        },
                    )),
                }
            }
            U64Segment::SortedArray(array) => Self {
                segment: Some(pb::u64_segment::Segment::SortedArray(array.into())),
            },
            U64Segment::Array(array) => Self {
                segment: Some(pb::u64_segment::Segment::Array(array.into())),
            },
        }
    }
}

impl From<EncodedU64Array> for pb::EncodedU64Array {
    fn from(array: EncodedU64Array) -> Self {
        match array {
            EncodedU64Array::U16 { base, offsets } => Self {
                array: Some(pb::encoded_u64_array::Array::U16Array(
                    pb::encoded_u64_array::U16Array {
                        base,
                        offsets: offsets
                            .iter()
                            .flat_map(|&offset| offset.to_le_bytes().to_vec())
                            .collect(),
                    },
                )),
            },
            EncodedU64Array::U32 { base, offsets } => Self {
                array: Some(pb::encoded_u64_array::Array::U32Array(
                    pb::encoded_u64_array::U32Array {
                        base,
                        offsets: offsets
                            .iter()
                            .flat_map(|&offset| offset.to_le_bytes().to_vec())
                            .collect(),
                    },
                )),
            },
            EncodedU64Array::U64(values) => Self {
                array: Some(pb::encoded_u64_array::Array::U64Array(
                    pb::encoded_u64_array::U64Array {
                        values: values
                            .iter()
                            .flat_map(|&value| value.to_le_bytes().to_vec())
                            .collect(),
                    },
                )),
            },
        }
    }
}

/// Serialize a rowid sequence to a buffer.
pub fn write_row_ids(sequence: &RowIdSequence) -> Vec<u8> {
    let pb_sequence = pb::RowIdSequence::from(sequence.clone());
    pb_sequence.encode_to_vec()
}

/// Deserialize a rowid sequence from some bytes.
/// Decode a serialized [`RowIdSequence`].
///
/// Pass a `Bytes` (for example the manifest's inline bytes) rather than a
/// `&[u8]` when possible: bitmap segments then slice the source buffer instead
/// of copying it.
pub fn read_row_ids(reader: impl Buf) -> Result<RowIdSequence> {
    let pb_sequence = pb::RowIdSequence::decode(reader).map_err(|error| {
        corrupt_row_id_metadata(format!("failed to decode row ID sequence: {error}"))
    })?;
    RowIdSequence::try_from(pb_sequence)
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    #[test]
    fn test_bitmap_serialization_is_byte_exact() {
        let mut bitmap = Bitmap::new_full(10);
        bitmap.clear(2);
        let segment = U64Segment::RangeWithBitmap {
            range: 100..110,
            bitmap,
        };
        assert_eq!(segment.len(), 9);

        let serialized = pb::U64Segment::from(segment.clone());
        let Some(pb::u64_segment::Segment::RangeWithBitmap(encoded)) = &serialized.segment else {
            panic!("expected bitmap segment");
        };
        assert_eq!(encoded.bitmap, vec![0xfb, 0x03]);
        assert_eq!(U64Segment::try_from(serialized).unwrap(), segment);
    }
    fn read_segment(segment: pb::u64_segment::Segment) -> Result<RowIdSequence> {
        let sequence = pb::RowIdSequence {
            segments: vec![pb::U64Segment {
                segment: Some(segment),
            }],
        };
        read_row_ids(sequence.encode_to_vec().as_slice())
    }

    fn assert_corrupt_segment(segment: pb::u64_segment::Segment, expected_message: &str) {
        let error = read_segment(segment).unwrap_err();
        assert!(matches!(&error, Error::CorruptFile { .. }));
        assert!(
            error.to_string().contains(expected_message),
            "expected error containing {expected_message:?}, got {error}"
        );
    }

    /// Each segment length fits a usize, but the aggregate does not fit a u64. Accepting
    /// this would leave `RowIdSequence::len()` overflowing for callers such as
    /// `Dataset::validate()`.
    #[test]
    fn test_reject_sequence_length_overflow() {
        let segment = || pb::U64Segment {
            segment: Some(pb::u64_segment::Segment::Range(pb::u64_segment::Range {
                start: 0,
                end: u64::MAX,
            })),
        };
        let sequence = pb::RowIdSequence {
            segments: vec![segment(), segment()],
        };

        let error = read_row_ids(sequence.encode_to_vec().as_slice()).unwrap_err();
        assert!(matches!(&error, Error::CorruptFile { .. }));
        assert!(
            error
                .to_string()
                .contains("total length exceeding u64::MAX"),
            "got {error}"
        );
    }

    #[test]
    fn test_write_read_row_ids() {
        let mut sequence = RowIdSequence::from(0..20);
        sequence.0.push(U64Segment::Range(30..100));
        sequence.0.push(U64Segment::RangeWithHoles {
            range: 100..200,
            holes: EncodedU64Array::U64(vec![104, 108, 150]),
        });
        let mut bitmap = Bitmap::new_empty(100);
        bitmap.set(99);
        sequence.0.push(U64Segment::RangeWithBitmap {
            range: 200..300,
            bitmap,
        });
        sequence
            .0
            .push(U64Segment::SortedArray(EncodedU64Array::U16 {
                base: 200,
                offsets: vec![1, 2, 3],
            }));
        sequence
            .0
            .push(U64Segment::Array(EncodedU64Array::U64(vec![3, 1, 2])));

        let serialized = write_row_ids(&sequence);

        let sequence2 = read_row_ids(serialized.as_slice()).unwrap();

        assert_eq!(sequence.0, sequence2.0);
    }

    proptest! {
        #[test]
        fn test_row_id_sequence_len_round_trips(
            values in proptest::collection::btree_set(any::<u64>(), 0..128)
        ) {
            let values = values.into_iter().collect::<Vec<_>>();
            let sequence = RowIdSequence::from(values.as_slice());
            let deserialized = read_row_ids(write_row_ids(&sequence).as_slice()).unwrap();

            prop_assert_eq!(deserialized.len(), sequence.len());
            prop_assert_eq!(deserialized.iter().collect::<Vec<_>>(), values);
        }

        #[test]
        fn test_rejects_wrong_range_with_bitmap_length(
            range_len in 1usize..512,
        ) {
            let expected_len = range_len.div_ceil(8);
            for actual_len in [expected_len - 1, expected_len + 1] {
                let segment = pb::u64_segment::Segment::RangeWithBitmap(
                    pb::u64_segment::RangeWithBitmap {
                        start: 0,
                        end: range_len as u64,
                        bitmap: vec![0; actual_len].into(),
                    },
                );

                let error = read_segment(segment).unwrap_err();
                let is_corrupt_file = matches!(&error, Error::CorruptFile { .. });
                prop_assert!(is_corrupt_file);
                prop_assert!(error.to_string().contains("byte length"));
            }
        }

        #[test]
        fn test_rejects_range_with_bitmap_padding_bits(
            full_bytes in 0usize..64,
            valid_bits in 1usize..8,
        ) {
            let range_len = full_bytes * 8 + valid_bits;
            let mut bitmap = vec![0; full_bytes + 1];
            bitmap[full_bytes] = 1 << valid_bits;
            let segment = pb::u64_segment::Segment::RangeWithBitmap(
                pb::u64_segment::RangeWithBitmap {
                    start: 0,
                    end: range_len as u64,
                    bitmap: bitmap.into(),
                },
            );

            let error = read_segment(segment).unwrap_err();
            let is_corrupt_file = matches!(&error, Error::CorruptFile { .. });
            prop_assert!(is_corrupt_file);
            prop_assert!(error.to_string().contains("padding bits must be zero"));
        }

        #[test]
        fn test_rejects_reversed_range_with_bitmap(
            start in 1u64..u64::MAX,
        ) {
            let segment = pb::u64_segment::Segment::RangeWithBitmap(
                pb::u64_segment::RangeWithBitmap {
                    start,
                    end: start - 1,
                    bitmap: Vec::new().into(),
                },
            );

            let error = read_segment(segment).unwrap_err();
            let is_corrupt_file = matches!(&error, Error::CorruptFile { .. });
            prop_assert!(is_corrupt_file);
            prop_assert!(error.to_string().contains("range start"));
        }

        #[test]
        fn test_rejects_misaligned_encoded_array_bytes(
            encoding in 0u8..3,
            element_count in 0usize..16,
        ) {
            let width = match encoding {
                0 => 2,
                1 => 4,
                _ => 8,
            };
            let bytes = vec![0; element_count * width + 1];
            let array = match encoding {
                0 => pb::encoded_u64_array::Array::U16Array(
                    pb::encoded_u64_array::U16Array { base: 0, offsets: bytes },
                ),
                1 => pb::encoded_u64_array::Array::U32Array(
                    pb::encoded_u64_array::U32Array { base: 0, offsets: bytes },
                ),
                _ => pb::encoded_u64_array::Array::U64Array(
                    pb::encoded_u64_array::U64Array { values: bytes },
                ),
            };
            let segment = pb::u64_segment::Segment::Array(pb::EncodedU64Array {
                array: Some(array),
            });

            let error = read_segment(segment).unwrap_err();
            let is_corrupt_file = matches!(&error, Error::CorruptFile { .. });
            prop_assert!(is_corrupt_file);
            prop_assert!(error.to_string().contains("byte length"));
        }
    }

    #[test]
    fn test_rejects_encoded_offset_overflow() {
        use pb::encoded_u64_array as pb_array;

        let arrays = [
            pb_array::Array::U16Array(pb_array::U16Array {
                base: u64::MAX,
                offsets: 1u16.to_le_bytes().to_vec(),
            }),
            pb_array::Array::U32Array(pb_array::U32Array {
                base: u64::MAX,
                offsets: 1u32.to_le_bytes().to_vec(),
            }),
        ];
        for array in arrays {
            assert_corrupt_segment(
                pb::u64_segment::Segment::Array(pb::EncodedU64Array { array: Some(array) }),
                "overflows u64",
            );
        }
    }

    #[rstest]
    #[case::descending(vec![6, 5], "not strictly increasing")]
    #[case::duplicate(vec![5, 5], "not strictly increasing")]
    #[case::below_range(vec![4], "outside the range")]
    #[case::at_end(vec![7], "outside the range")]
    fn test_rejects_invalid_range_with_holes(#[case] values: Vec<u64>, #[case] message: &str) {
        let values = values.into_iter().flat_map(u64::to_le_bytes).collect();
        assert_corrupt_segment(
            pb::u64_segment::Segment::RangeWithHoles(pb::u64_segment::RangeWithHoles {
                start: 5,
                end: 7,
                holes: Some(pb::EncodedU64Array {
                    array: Some(pb::encoded_u64_array::Array::U64Array(
                        pb::encoded_u64_array::U64Array { values },
                    )),
                }),
            }),
            message,
        );
    }

    #[test]
    fn test_rejects_missing_range_with_holes_array() {
        assert_corrupt_segment(
            pb::u64_segment::Segment::RangeWithHoles(pb::u64_segment::RangeWithHoles {
                start: 5,
                end: 7,
                holes: None,
            }),
            "missing its holes array",
        );
    }

    #[rstest]
    #[case::u16(
        pb::encoded_u64_array::Array::U16Array(pb::encoded_u64_array::U16Array {
            base: 0,
            offsets: vec![1],
        }),
        "encoded u16 array byte length 1 is not a multiple of element width 2"
    )]
    #[case::u32(
        pb::encoded_u64_array::Array::U32Array(pb::encoded_u64_array::U32Array {
            base: 0,
            offsets: vec![1, 2, 3],
        }),
        "encoded u32 array byte length 3 is not a multiple of element width 4"
    )]
    #[case::u64(
        pb::encoded_u64_array::Array::U64Array(pb::encoded_u64_array::U64Array {
            values: vec![1, 2, 3, 4, 5, 6, 7],
        }),
        "encoded u64 array byte length 7 is not a multiple of element width 8"
    )]
    fn test_rejects_misaligned_encoded_array(
        #[case] array: pb::encoded_u64_array::Array,
        #[case] message: &str,
    ) {
        assert_corrupt_segment(
            pb::u64_segment::Segment::Array(pb::EncodedU64Array { array: Some(array) }),
            message,
        );
    }

    #[rstest]
    #[case::range(pb::u64_segment::Segment::Range(pb::u64_segment::Range {
        start: 10,
        end: 9,
    }))]
    #[case::range_with_holes(pb::u64_segment::Segment::RangeWithHoles(
        pb::u64_segment::RangeWithHoles {
            start: 10,
            end: 9,
            holes: Some(pb::EncodedU64Array {
                array: Some(pb::encoded_u64_array::Array::U64Array(
                    pb::encoded_u64_array::U64Array { values: Vec::new() },
                )),
            }),
        }
    ))]
    #[case::range_with_bitmap(pb::u64_segment::Segment::RangeWithBitmap(
        pb::u64_segment::RangeWithBitmap {
            start: 10,
            end: 9,
            bitmap: Vec::new().into(),
        }
    ))]
    fn test_rejects_reversed_range(#[case] segment: pb::u64_segment::Segment) {
        assert_corrupt_segment(segment, "range start 10 exceeds end 9");
    }

    #[rstest]
    #[case::short(vec![0])]
    #[case::long(vec![0, 0, 0])]
    fn test_rejects_incorrect_bitmap_length(#[case] bitmap: Vec<u8>) {
        assert_corrupt_segment(
            pb::u64_segment::Segment::RangeWithBitmap(pb::u64_segment::RangeWithBitmap {
                start: 5,
                end: 14,
                bitmap: bitmap.into(),
            }),
            "does not match expected 2 for range start 5, end 14, and length 9",
        );
    }

    #[test]
    fn test_rejects_set_bitmap_padding_bits() {
        assert_corrupt_segment(
            pb::u64_segment::Segment::RangeWithBitmap(pb::u64_segment::RangeWithBitmap {
                start: 5,
                end: 14,
                bitmap: vec![0xff, 0x03].into(),
            }),
            "padding bits must be zero",
        );
    }

    #[rstest]
    #[case::u16(pb::encoded_u64_array::Array::U16Array(
        pb::encoded_u64_array::U16Array {
            base: 100,
            offsets: vec![2, 0, 1, 0],
        }
    ))]
    #[case::u32(pb::encoded_u64_array::Array::U32Array(
        pb::encoded_u64_array::U32Array {
            base: 100,
            offsets: vec![2, 0, 0, 0, 1, 0, 0, 0],
        }
    ))]
    #[case::u64(pb::encoded_u64_array::Array::U64Array(
        pb::encoded_u64_array::U64Array {
            values: vec![2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        }
    ))]
    fn test_rejects_unsorted_sorted_array(#[case] array: pb::encoded_u64_array::Array) {
        assert_corrupt_segment(
            pb::u64_segment::Segment::SortedArray(pb::EncodedU64Array { array: Some(array) }),
            "SortedArray values are not sorted at indices 0 and 1: 2 exceeds 1",
        );
    }

    #[test]
    fn test_read_row_ids_from_bytes_shares_bitmap_buffer() {
        let mut bitmap = Bitmap::new_full(4096);
        for hole in (0..4096).step_by(7) {
            bitmap.clear(hole);
        }
        let sequence = RowIdSequence(vec![U64Segment::RangeWithBitmap {
            range: 10..4106,
            bitmap,
        }]);
        let encoded = bytes::Bytes::from(write_row_ids(&sequence));
        let decoded = read_row_ids(encoded.clone()).unwrap();
        assert_eq!(decoded, sequence);
        let U64Segment::RangeWithBitmap { bitmap, .. } = &decoded.0[0] else {
            panic!("expected a bitmap segment");
        };
        let start = encoded.as_ptr() as usize;
        let ptr = bitmap.bytes().as_ptr() as usize;
        assert!(
            (start..start + encoded.len()).contains(&ptr),
            "decoded bitmap must slice the encoded buffer"
        );
    }

    #[test]
    fn test_range_with_runs_round_trip_and_validation() {
        let runs = HoleRuns::try_new(50, vec![3, 20], vec![10, 45]).unwrap();
        let sequence = RowIdSequence(vec![U64Segment::RangeWithRuns {
            range: 100..150,
            runs,
        }]);
        let decoded = read_row_ids(write_row_ids(&sequence).as_slice()).unwrap();
        assert_eq!(decoded, sequence);
        assert_eq!(decoded.len(), 50 - 7 - 25);

        use pb::u64_segment::{RangeWithRuns, Segment};
        let encode = |start: u64, end: u64, starts: Option<Vec<u64>>, ends: Option<Vec<u64>>| {
            pb::RowIdSequence {
                segments: vec![pb::U64Segment {
                    segment: Some(Segment::RangeWithRuns(RangeWithRuns {
                        start,
                        end,
                        hole_starts: starts.map(|s| EncodedU64Array::from(s).into()),
                        hole_ends: ends.map(|e| EncodedU64Array::from(e).into()),
                    })),
                }],
            }
            .encode_to_vec()
        };
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "span over u32",
                encode(0, 1 << 33, Some(vec![1]), Some(vec![2])),
            ),
            ("missing ends", encode(0, 50, Some(vec![1]), None)),
            (
                "unsorted",
                encode(0, 50, Some(vec![20, 3]), Some(vec![25, 10])),
            ),
            (
                "adjacent",
                encode(0, 50, Some(vec![3, 10]), Some(vec![10, 12])),
            ),
            ("beyond span", encode(0, 50, Some(vec![3]), Some(vec![51]))),
        ];
        for (name, bytes) in cases {
            let error = read_row_ids(bytes.as_slice()).unwrap_err();
            assert!(
                error.to_string().contains("RangeWithRuns"),
                "{name}: {error}"
            );
        }
    }
}
