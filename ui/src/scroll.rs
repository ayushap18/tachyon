//! Preserve high-resolution wheel movement instead of rounding each event to a row.

#[derive(Default)]
pub(crate) struct ScrollAccumulator {
    rows: f64,
}

impl ScrollAccumulator {
    pub fn push(&mut self, delta: f64, mode: u32, cell_height: f64, page_rows: u16) {
        if !delta.is_finite() || !cell_height.is_finite() || cell_height <= 0.0 {
            return;
        }
        let rows = match mode {
            1 => delta,
            2 => delta * f64::from(page_rows),
            _ => delta / cell_height,
        };
        // Reversing a gesture should respond immediately, without paying off the
        // previous direction's fractional remainder.
        if self.rows.signum() == rows.signum() {
            self.rows = 0.0;
        }
        self.rows = (self.rows - rows).clamp(-5000.0, 5000.0);
    }

    pub fn take(&mut self) -> i32 {
        let whole = self.rows.trunc() as i32;
        self.rows -= f64::from(whole);
        whole
    }

    pub fn has_rows(&self) -> bool {
        self.rows.abs() >= 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trackpad_preserves_fractional_movement_across_frames() {
        let mut scroll = ScrollAccumulator::default();
        for _ in 0..3 {
            scroll.push(-4.0, 0, 16.0, 30);
            assert_eq!(scroll.take(), 0);
        }
        scroll.push(-6.0, 0, 16.0, 30);
        assert_eq!(scroll.take(), 1);
        scroll.push(-14.0, 0, 16.0, 30);
        assert_eq!(scroll.take(), 1);
    }

    #[test]
    fn honors_line_and_page_units_and_ignores_horizontal_movement() {
        let mut scroll = ScrollAccumulator::default();
        scroll.push(3.0, 1, 16.0, 30);
        assert_eq!(scroll.take(), -3);
        scroll.push(-1.0, 2, 16.0, 30);
        assert_eq!(scroll.take(), 30);
        scroll.push(0.0, 0, 16.0, 30);
        assert_eq!(scroll.take(), 0);
    }

    #[test]
    fn reversal_discards_old_remainder_and_invalid_input_is_ignored() {
        let mut scroll = ScrollAccumulator::default();
        scroll.push(-15.0, 0, 16.0, 30);
        scroll.push(16.0, 0, 16.0, 30);
        assert_eq!(scroll.take(), -1);
        scroll.push(f64::NAN, 0, 16.0, 30);
        scroll.push(f64::INFINITY, 0, 16.0, 30);
        assert_eq!(scroll.take(), 0);
    }
}
