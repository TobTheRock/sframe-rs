#[cfg(test)]
use std::fmt::Write;

#[cfg(test)]
pub(crate) fn bin2string(bin: &[u8]) -> String {
    bin.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:08b} ");
        output
    })
}

#[cfg(test)]
pub mod test {
    use super::bin2string;
    use pretty_assertions::assert_eq;

    #[allow(clippy::missing_panics_doc)]
    pub fn assert_bytes_eq(l: &[u8], r: &[u8]) {
        assert_eq!(bin2string(l), bin2string(r));
    }
}
