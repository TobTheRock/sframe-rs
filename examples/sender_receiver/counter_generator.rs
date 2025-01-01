use sframe::header::Counter;

#[derive(Copy, Clone, Debug)]
pub struct CounterGenerator {
    current_counter: u64,
    max_counter: u64,
}

impl CounterGenerator {
    pub fn new(max_counter: u64) -> Self {
        Self {
            current_counter: 0,
            max_counter,
        }
    }

    pub fn increment(&mut self) -> Counter {
        let counter = self.current_counter;
        self.current_counter = self.current_counter.wrapping_add(1);

        if self.current_counter > self.max_counter {
            self.current_counter = 0;
        }

        counter
    }
}

impl Default for CounterGenerator {
    fn default() -> Self {
        Self {
            current_counter: 0,
            max_counter: u64::MAX,
        }
    }
}

#[cfg(test)]
mod test {
    use super::CounterGenerator;
    use pretty_assertions::assert_eq;

    #[test]
    fn create_increasing_counters() {
        let mut counter_generator = CounterGenerator::default();

        for i in 0..10 {
            assert_eq!(counter_generator.increment(), i);
        }
    }
    #[test]
    fn wraps_after_u64_max_was_reached() {
        let mut counter_generator = CounterGenerator::new(u64::MAX);

        counter_generator.current_counter = u64::MAX - 1;

        assert_eq!(counter_generator.increment(), u64::MAX - 1);
        assert_eq!(counter_generator.increment(), u64::MAX);
        assert_eq!(counter_generator.increment(), 0);
    }

    #[test]
    fn wraps_after_max_counter_was_reached() {
        let max_counter = 1;
        let mut counter_generator = CounterGenerator::new(max_counter);

        assert_eq!(counter_generator.increment(), 0);
        assert_eq!(counter_generator.increment(), 1);
        assert_eq!(counter_generator.increment(), 0);
    }
}
