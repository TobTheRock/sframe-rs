// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use crate::header::FrameCount;

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct FrameCountGenerator {
    current_frame_count: u64,
}

impl FrameCountGenerator {
    const MAX_FRAME_COUNT: u64 = u64::MAX;

    pub fn increment(&mut self) -> FrameCount {
        let frame_count = self.current_frame_count;
        self.current_frame_count =
            (self.current_frame_count + 1) % FrameCountGenerator::MAX_FRAME_COUNT;
        frame_count
    }
}

#[cfg(test)]
mod test {
    use super::FrameCountGenerator;
    use pretty_assertions::assert_eq;

    #[test]
    fn create_increasing_frame_counts() {
        let mut frame_count_generator = FrameCountGenerator::default();

        for i in 0..10 {
            assert_eq!(frame_count_generator.increment(), i);
        }
    }
}
