//! Writing: a tag, the shortest definite length, the contents.

/// One tag, length and contents.
#[must_use]
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + contents.len());
    write_tlv(&mut out, tag, contents);
    out
}

/// Append one tag, length and contents to `out`.
pub fn write_tlv(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    write_length(out, contents.len());
    out.extend_from_slice(contents);
}

/// A length, short form under 128 and the fewest bytes of long form from
/// there.
fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0x7f));
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    out.push(0x80 | u8::try_from(bytes.len() - first).unwrap_or(0));
    out.extend_from_slice(&bytes[first..]);
}

/// An `INTEGER`'s contents: two's complement, the fewest bytes that keep the
/// sign. The tag is the caller's, since `ENUMERATED` and an implicitly tagged
/// integer are written the same way.
#[must_use]
pub fn integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut first = 0;
    while first + 1 < bytes.len() {
        let sign_extends = (bytes[first] == 0x00 && bytes[first + 1] & 0x80 == 0)
            || (bytes[first] == 0xff && bytes[first + 1] & 0x80 != 0);
        if !sign_extends {
            break;
        }
        first += 1;
    }
    bytes[first..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NULL, OCTET_STRING, read_integer};

    #[test]
    fn a_length_is_short_below_128_and_the_fewest_long_bytes_from_there() {
        assert_eq!(tlv(OCTET_STRING, b"hi"), [0x04, 2, b'h', b'i']);
        assert_eq!(&tlv(OCTET_STRING, &[7; 128])[..3], &[0x04, 0x81, 0x80]);
        assert_eq!(
            &tlv(OCTET_STRING, &[7; 300])[..4],
            &[0x04, 0x82, 0x01, 0x2c]
        );
        let mut appended = vec![0xff];
        write_tlv(&mut appended, NULL, &[]);
        assert_eq!(appended, [0xff, NULL, 0]);
    }

    #[test]
    fn integers_are_the_shortest_twos_complement() {
        for (value, bytes) in [
            (0, vec![0x00]),
            (1, vec![0x01]),
            (127, vec![0x7f]),
            (128, vec![0x00, 0x80]),
            (-1, vec![0xff]),
            (-128, vec![0x80]),
            (-129, vec![0xff, 0x7f]),
            (65_535, vec![0x00, 0xff, 0xff]),
        ] {
            assert_eq!(integer(value), bytes, "{value}");
            assert_eq!(read_integer(&bytes).expect("read"), value, "{value}");
        }
        for value in [i64::MAX, i64::MIN] {
            assert_eq!(read_integer(&integer(value)).expect("read"), value);
        }
    }
}
