// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The Lance Authors

//! Run-length encoded holes of a [`U64Segment::RangeWithRuns`](super::U64Segment).

use std::ops::Range;

use lance_core::Result;
use lance_core::deepsize::DeepSizeOf;

use super::bitmap::Bitmap;
use super::serde::corrupt_row_id_metadata;

/// The missing offsets of a range, as maximal runs.
///
/// Offsets are relative to the range start and fit `u32`, which bounds the span
/// of a range this encoding can describe to `u32::MAX`; a fragment never holds
/// more rows than that, and writers fall back to another encoding for wider
/// spans. Compared to a bitmap this costs 8 bytes per run rather than one bit
/// per offset, so it pays off exactly when deletions cluster, as they do after
/// compaction of fragments with deleted rows.
#[derive(Debug, Clone, PartialEq, Eq, DeepSizeOf)]
pub struct HoleRuns {
    /// Length of the range the runs live in (offsets are below this).
    span: u32,
    /// First missing offset of each run, strictly increasing.
    starts: Vec<u32>,
    /// First offset after each run: `starts[i] < ends[i] < starts[i + 1]`.
    ends: Vec<u32>,
    /// `missing_before[k]` is the number of offsets missing in runs `0..k`, so it
    /// has one entry per run plus a final total.
    missing_before: Vec<u32>,
}

impl HoleRuns {
    /// Build from validated run bounds. Rejects runs that are empty, out of
    /// order, overlapping, adjacent (a maximal run never touches the next) or
    /// beyond `span`.
    pub fn try_new(span: u32, starts: Vec<u32>, ends: Vec<u32>) -> Result<Self> {
        if starts.len() != ends.len() {
            return Err(corrupt_row_id_metadata(format!(
                "RangeWithRuns has {} run starts but {} run ends",
                starts.len(),
                ends.len()
            )));
        }
        let mut missing_before = Vec::with_capacity(starts.len() + 1);
        let mut missing: u32 = 0;
        let mut previous_end: Option<u32> = None;
        for (i, (&start, &end)) in starts.iter().zip(&ends).enumerate() {
            if start >= end {
                return Err(corrupt_row_id_metadata(format!(
                    "RangeWithRuns run {i} is empty or reversed: {start}..{end}"
                )));
            }
            if end > span {
                return Err(corrupt_row_id_metadata(format!(
                    "RangeWithRuns run {i} ({start}..{end}) ends beyond the span {span}"
                )));
            }
            if let Some(previous_end) = previous_end
                && previous_end >= start
            {
                return Err(corrupt_row_id_metadata(format!(
                    "RangeWithRuns run {i} starts at {start}, but the previous run ends at \
                     {previous_end}: runs must be sorted, disjoint and non-adjacent"
                )));
            }
            missing_before.push(missing);
            missing = missing.checked_add(end - start).ok_or_else(|| {
                corrupt_row_id_metadata(format!(
                    "RangeWithRuns misses more than u32::MAX offsets by run {i}"
                ))
            })?;
            previous_end = Some(end);
        }
        missing_before.push(missing);
        Ok(Self {
            span,
            starts,
            ends,
            missing_before,
        })
    }

    /// Runs over the sorted, unique missing `offsets` (all below `span`).
    pub fn from_missing_offsets(span: u32, offsets: impl IntoIterator<Item = u32>) -> Self {
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for offset in offsets {
            match ends.last_mut() {
                Some(end) if *end == offset => *end += 1,
                _ => {
                    starts.push(offset);
                    ends.push(offset + 1);
                }
            }
        }
        Self::try_new(span, starts, ends).expect("sorted unique offsets form valid runs")
    }

    /// The runs of cleared bits of `bitmap`.
    pub fn from_bitmap(bitmap: &Bitmap) -> Self {
        let span = bitmap.len();
        debug_assert!(span <= u32::MAX as usize, "bitmap spans exceed u32");
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        let mut open_run: Option<u32> = None;
        let mut offset: usize = 0;
        for &byte in bitmap.bytes() {
            let valid_bits = (span - offset).min(8);
            // Bits past `span` read as present so they never open a run.
            let mut present = byte | (u8::MAX.checked_shl(valid_bits as u32).unwrap_or(0));
            if present == u8::MAX {
                if let Some(start) = open_run.take() {
                    starts.push(start);
                    ends.push(offset as u32);
                }
            } else if present == 0 {
                open_run.get_or_insert(offset as u32);
            } else {
                for bit in 0..valid_bits {
                    let is_present = present & 1 != 0;
                    present >>= 1;
                    let here = (offset + bit) as u32;
                    match (is_present, open_run) {
                        (false, None) => open_run = Some(here),
                        (true, Some(start)) => {
                            starts.push(start);
                            ends.push(here);
                            open_run = None;
                        }
                        _ => {}
                    }
                }
            }
            offset += 8;
            if offset >= span {
                break;
            }
        }
        if let Some(start) = open_run {
            starts.push(start);
            ends.push(span as u32);
        }
        Self::try_new(span as u32, starts, ends).expect("runs derived from a bitmap are valid")
    }

    /// Length of the range the runs live in.
    pub fn span(&self) -> u32 {
        self.span
    }

    pub fn num_runs(&self) -> usize {
        self.starts.len()
    }

    /// First missing offset of each run.
    pub fn starts(&self) -> &[u32] {
        &self.starts
    }

    /// First offset after each run.
    pub fn ends(&self) -> &[u32] {
        &self.ends
    }

    /// Offsets missing over the whole span.
    pub fn missing_total(&self) -> u32 {
        *self.missing_before.last().expect("always holds the total")
    }

    /// Offsets present over the whole span.
    pub fn present_len(&self) -> u32 {
        self.span - self.missing_total()
    }

    /// Runs whose start is at or before `offset`.
    fn runs_started_by(&self, offset: u32) -> usize {
        self.starts.partition_point(|&start| start <= offset)
    }

    /// Present offsets before run `k` (`k == num_runs` counts every present offset).
    fn present_before_run(&self, k: usize) -> u32 {
        let run_start = self.starts.get(k).copied().unwrap_or(self.span);
        run_start - self.missing_before[k]
    }

    /// Runs that lie entirely before the present value at `position`: those
    /// whose preceding present count is at most `position`. That count is
    /// non-decreasing in the run index, so this is a binary search.
    fn runs_before_position(&self, position: u32) -> usize {
        let mut lo = 0usize;
        let mut hi = self.starts.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.present_before_run(mid) <= position {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Position of the present `offset`, or `None` when it is missing or out of range.
    pub fn position(&self, offset: u32) -> Option<u32> {
        if offset >= self.span {
            return None;
        }
        let k = self.runs_started_by(offset);
        if k > 0 && offset < self.ends[k - 1] {
            return None;
        }
        Some(offset - self.missing_before[k])
    }

    /// Offset of the present value at `position`.
    pub fn offset_at(&self, position: u32) -> Option<u32> {
        if position >= self.present_len() {
            return None;
        }
        let k = self.runs_before_position(position);
        Some(position + self.missing_before[k])
    }

    /// The present offsets, as the maximal ranges between runs.
    pub fn present_ranges(&self) -> impl DoubleEndedIterator<Item = Range<u32>> + '_ {
        (0..=self.starts.len())
            .map(move |k| {
                let start = if k == 0 { 0 } else { self.ends[k - 1] };
                let end = self.starts.get(k).copied().unwrap_or(self.span);
                start..end
            })
            .filter(|range| !range.is_empty())
    }

    /// Append `base + offset` for the present offsets at `positions`.
    pub fn extend_values(&self, base: u64, positions: Range<u32>, values: &mut Vec<u64>) {
        let end = positions.end.min(self.present_len());
        let mut position = positions.start;
        if position >= end {
            return;
        }
        let mut k = self.runs_before_position(position);
        while position < end {
            // Present range between run k - 1 and run k, in offsets and positions.
            let gap_start = if k == 0 { 0 } else { self.ends[k - 1] };
            let gap_end = self.starts.get(k).copied().unwrap_or(self.span);
            let first_position = gap_start - self.missing_before[k];
            let gap_positions = first_position..first_position + (gap_end - gap_start);
            let take = position.max(gap_positions.start)..end.min(gap_positions.end);
            if !take.is_empty() {
                let offset = gap_start + (take.start - gap_positions.start);
                values.extend((base + offset as u64)..(base + offset as u64 + take.len() as u64));
                position = take.end;
            }
            k += 1;
            if k > self.starts.len() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs() -> HoleRuns {
        // span 20: present 0..3, missing 3..7, present 7..8, missing 8..15, present 15..20
        HoleRuns::try_new(20, vec![3, 8], vec![7, 15]).unwrap()
    }

    #[test]
    fn test_counts_and_ranges() {
        let runs = runs();
        assert_eq!(runs.missing_total(), 11);
        assert_eq!(runs.present_len(), 9);
        assert_eq!(
            runs.present_ranges().collect::<Vec<_>>(),
            vec![0..3, 7..8, 15..20]
        );
        assert_eq!(
            runs.present_ranges().rev().collect::<Vec<_>>(),
            vec![15..20, 7..8, 0..3]
        );
    }

    #[test]
    fn test_position_and_offset_round_trip() {
        let runs = runs();
        let present: Vec<u32> = runs.present_ranges().flatten().collect();
        assert_eq!(present, vec![0, 1, 2, 7, 15, 16, 17, 18, 19]);
        for (position, &offset) in present.iter().enumerate() {
            assert_eq!(
                runs.position(offset),
                Some(position as u32),
                "offset {offset}"
            );
            assert_eq!(
                runs.offset_at(position as u32),
                Some(offset),
                "position {position}"
            );
        }
        for missing in [3, 4, 6, 8, 14, 20, 100] {
            assert_eq!(runs.position(missing), None, "offset {missing}");
        }
        assert_eq!(runs.offset_at(9), None);
    }

    #[test]
    fn test_extend_values_crosses_runs() {
        let runs = runs();
        let mut values = Vec::new();
        runs.extend_values(100, 1..7, &mut values);
        assert_eq!(values, vec![101, 102, 107, 115, 116, 117]);
        values.clear();
        runs.extend_values(100, 4..40, &mut values);
        assert_eq!(values, vec![115, 116, 117, 118, 119]);
        values.clear();
        runs.extend_values(100, 9..12, &mut values);
        assert!(values.is_empty());
    }

    #[test]
    fn test_from_bitmap_matches_cleared_bits() {
        for (len, cleared) in [
            (20usize, vec![3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14]),
            (1, vec![0]),
            (9, vec![]),
            (17, vec![0, 16]),
            (64, (8..56).collect()),
            (70, vec![7, 8, 9, 15, 16, 63, 64, 65, 66, 67, 68, 69]),
        ] {
            let bitmap = Bitmap::new_full_except(len, cleared.iter().copied());
            let runs = HoleRuns::from_bitmap(&bitmap);
            let missing: Vec<u32> = (0..len as u32)
                .filter(|offset| runs.position(*offset).is_none())
                .collect();
            assert_eq!(
                missing,
                cleared.iter().map(|&c| c as u32).collect::<Vec<_>>(),
                "len {len}"
            );
            assert_eq!(runs.missing_total() as usize, cleared.len());
            // Runs are maximal.
            for pair in runs
                .starts()
                .iter()
                .zip(runs.ends())
                .collect::<Vec<_>>()
                .windows(2)
            {
                assert!(pair[0].1 < pair[1].0);
            }
        }
    }

    #[test]
    fn test_try_new_rejects_malformed_runs() {
        let cases: [(&str, Vec<u32>, Vec<u32>); 5] = [
            ("length mismatch", vec![1], vec![]),
            ("empty run", vec![3], vec![3]),
            ("beyond span", vec![3], vec![21]),
            ("overlapping", vec![3, 5], vec![7, 9]),
            ("adjacent", vec![3, 7], vec![7, 9]),
        ];
        for (name, starts, ends) in cases {
            let error = HoleRuns::try_new(20, starts, ends).unwrap_err();
            assert!(
                error.to_string().contains("RangeWithRuns"),
                "{name}: {error}"
            );
        }
    }
}
