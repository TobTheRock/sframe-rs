pub struct SlidingWindow {
    offset: usize,
    size: usize,
    ring_buf: Box<[BitMask]>,
}

impl SlidingWindow {
    pub fn new(size: usize) -> Self {
        let buf_len: usize = size.div_ceil(BIT_MASK_LEN);
        Self {
            offset: 0,
            size,
            ring_buf: vec![0; buf_len].into_boxed_slice(),
        }
    }

    /// virtual shifts the buffer, unseting older indices by the same amount
    /// - If `shift > size` all bits are unset
    pub fn shift_right(&mut self, shift: usize) {
        if shift >= self.size {
            self.ring_buf.fill(0);
            self.offset = 0;
            return;
        }

        for idx in 0..shift {
            self.clear(idx);
        }
        self.offset = (self.offset + shift) % self.size;
    }

    pub fn is_set(&self, idx: usize) -> bool {
        debug_assert!(
            idx < self.size,
            "idx {idx} out of window bounds {}",
            self.size
        );
        if idx >= self.size {
            return false;
        }

        let (mask_idx, bit_idx) = self.sub_indices(idx);
        let mask = self.ring_buf[mask_idx];

        mask & (1 << bit_idx) != 0
    }

    pub fn set(&mut self, idx: usize) {
        debug_assert!(
            idx < self.size,
            "idx {idx} out of window bounds {}",
            self.size
        );
        if idx >= self.size {
            return;
        }

        let (mask_idx, bit_idx) = self.sub_indices(idx);
        let mask = self.ring_buf[mask_idx];

        self.ring_buf[mask_idx] = mask | (1 << bit_idx);
    }

    fn sub_indices(&self, idx: usize) -> (usize, usize) {
        let idx = (idx + self.offset) % self.size;

        let mask_idx = idx / BIT_MASK_LEN;
        let bit_idx = idx % BIT_MASK_LEN;

        (mask_idx, bit_idx)
    }

    fn clear(&mut self, idx: usize) {
        let (mask_idx, bit_idx) = self.sub_indices(idx);
        let mask = self.ring_buf[mask_idx];

        self.ring_buf[mask_idx] = mask & !(1 << bit_idx);
    }
}

type BitMask = u8;
const BIT_MASK_LEN: usize = 8;

#[cfg(test)]
mod test {
    use super::SlidingWindow;
    use test_case::test_case;

    const LESS_THEN_BYTE: usize = 7;
    const POWER_OF_TWO: usize = 64;
    const ARBITRARY: usize = 73;

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn bits_set_with_size(size: usize) {
        let mut win = SlidingWindow::new(size);

        for idx in 0..size {
            win.set(idx);
            assert!(win.is_set(idx), "Index {idx} not set");
        }
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    #[should_panic(expected = "out of window bounds")]
    fn set_out_of_bounds_panics(size: usize) {
        let mut win = SlidingWindow::new(size);
        // `size` itself is the first out-of-bounds index (valid range is 0..size).
        // Out-of-range is a caller bug (bad counter->slot mapping), not tolerated
        // input: silently no-oping would let replay detection fail open.
        win.set(size);
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn shifts_less_then_a_byte(size: usize) {
        assert_shifted(size, 3);
    }

    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn shifts_more_then_a_byte(size: usize) {
        assert_shifted(size, 14);
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn shifts_wraparound(size: usize) {
        assert_shifted(size, size - 1);
    }

    fn assert_shifted(size: usize, shift: usize) {
        let mut win = window_all_set(size);
        win.shift_right(shift);

        let kept_idx = size - shift;
        for idx in 0..kept_idx {
            assert!(win.is_set(idx), "Index {idx} should keep its value");
        }
        for idx in kept_idx..size {
            assert!(!win.is_set(idx), "Index {idx} should be a fresh slot");
        }
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn shift_moves_survivor_down(size: usize) {
        let mut win = SlidingWindow::new(size);
        win.set(size - 1);
        win.shift_right(1);

        assert!(
            win.is_set(size - 2),
            "retained mark should move one slot down"
        );
        assert!(
            !win.is_set(size - 1),
            "newest slot should be reopened fresh"
        );
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn shift_drops_oldest(size: usize) {
        let mut win = SlidingWindow::new(size);
        win.set(0);
        win.shift_right(1);

        for idx in 0..size {
            assert!(!win.is_set(idx), "dropped oldest reappeared at {idx}");
        }
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn repeated_shifts_add_up(size: usize) {
        let mut win = window_all_set(size);
        win.shift_right(3);
        win.shift_right(3);

        for idx in 0..(size - 6) {
            assert!(win.is_set(idx), "Index {idx} should keep its value");
        }
        for idx in (size - 6)..size {
            assert!(!win.is_set(idx), "Index {idx} should be a fresh slot");
        }
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn fresh_slots_are_settable_after_shift(size: usize) {
        let mut win = window_all_set(size);
        win.shift_right(2);

        let fresh = size - 1;
        assert!(!win.is_set(fresh));
        win.set(fresh);
        assert!(win.is_set(fresh), "fresh slot {fresh} not settable");
    }

    #[test_case(LESS_THEN_BYTE; "LessThenByte")]
    #[test_case(POWER_OF_TWO; "PowerOfTwo")]
    #[test_case(ARBITRARY; "Arbitrary")]
    fn unsets_all_with_shift_greater_than_size(size: usize) {
        let mut win = window_all_set(size);
        win.shift_right(size);

        for idx in 0..size {
            assert!(!win.is_set(idx), "Index {idx} wrongly set");
        }
    }

    fn window_all_set(size: usize) -> SlidingWindow {
        let mut win = SlidingWindow::new(size);
        for idx in 0..size {
            win.set(idx);
        }

        win
    }
}
