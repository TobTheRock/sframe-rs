use crate::header::FrameCount;

#[derive(Copy, Clone, Debug)]
pub struct FrameCountGenerator {
    current_frame_count: u64,
    max_frame_count: u64,
}

impl FrameCountGenerator {
    pub fn new(max_frame_count: u64) -> Self {
        Self {
            current_frame_count: 0,
            max_frame_count,
        }
    }

    pub fn increment(&mut self) -> FrameCount {
        let frame_count = self.current_frame_count;
        self.current_frame_count = self.current_frame_count.wrapping_add(1);

        if self.current_frame_count > self.max_frame_count {
            self.current_frame_count = 0;
        }

        frame_count
    }
}

impl Default for FrameCountGenerator {
    fn default() -> Self {
        Self {
            current_frame_count: 0,
            max_frame_count: u64::MAX,
        }
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
    #[test]
    fn wraps_after_u64_max_was_reached() {
        let mut frame_count_generator = FrameCountGenerator::new(u64::MAX);

        frame_count_generator.current_frame_count = u64::MAX - 1;

        assert_eq!(frame_count_generator.increment(), u64::MAX - 1);
        assert_eq!(frame_count_generator.increment(), u64::MAX);
        assert_eq!(frame_count_generator.increment(), 0);
    }

    #[test]
    fn wraps_after_max_frame_count_was_reached() {
        let max_frame_count = 1;
        let mut frame_count_generator = FrameCountGenerator::new(max_frame_count);

        assert_eq!(frame_count_generator.increment(), 0);
        assert_eq!(frame_count_generator.increment(), 1);
        assert_eq!(frame_count_generator.increment(), 0);
    }
}
