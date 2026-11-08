//! The contents of an `OBJECT IDENTIFIER` (X.690 8.19): the first two arcs
//! folded into one as `40 * first + second`, then every arc in base 128,
//! the high bit set on every byte but an arc's last.
//!
//! Here beside [`crate::integer`] because it is a universal type's content
//! encoding, which no protocol owns: SNMP carried the only copy until
//! 2026-09-24. So is the dotted text an identifier is written in (X.660),
//! `1.3.6.1.2.1.1.3.0`, which SNMP carried until 2026-09-28.

use crate::{Asn1Error, Result};

/// The dotted text of `arcs`: `1.3.6.1.2.1.1.3.0`.
#[must_use]
pub fn dotted(arcs: &[u32]) -> String {
    let mut text = String::with_capacity(arcs.len() * 4);
    for (index, arc) in arcs.iter().enumerate() {
        if index > 0 {
            text.push('.');
        }
        text.push_str(&arc.to_string());
    }
    text
}

/// The arcs dotted text names, a leading dot allowed (`.1.3.6`); `None`
/// where any arc is not a number that fits 32 bits, or the first two are
/// no identifier's: a first arc other than 0, 1 or 2 (X.660), a second over
/// 39 under 0 or 1, or the two folded past the 32 bits
/// [`read_object_identifier`] reads back. What it gives, every identifier
/// Xmip reads from text, is written and read back as itself.
#[must_use]
pub fn read_dotted(text: &str) -> Option<Vec<u32>> {
    let text = text.strip_prefix('.').unwrap_or(text);
    let arcs: Vec<u32> = text
        .split('.')
        .map(|arc| arc.parse().ok())
        .collect::<Option<_>>()?;
    let first = arcs.first().copied().unwrap_or(0);
    let second = arcs.get(1).copied().unwrap_or(0);
    let rooted = (first < 2 && second < 40) || (first == 2 && u32::try_from(folded(&arcs)).is_ok());
    rooted.then_some(arcs)
}

/// The first two arcs folded into one, `40 * first + second`, in 64 bits,
/// where no two 32-bit arcs overflow.
fn folded(arcs: &[u32]) -> u64 {
    let first = u64::from(arcs.first().copied().unwrap_or(0));
    first * 40 + u64::from(arcs.get(1).copied().unwrap_or(0))
}

/// The contents that encode `arcs`. An identifier of fewer than two arcs is
/// written as though the missing ones were zero. The first two are folded
/// in 64 bits, so no arcs overflow the fold; arcs [`read_dotted`] would
/// refuse are written as X.690 spells them and are not read back as
/// themselves.
#[must_use]
pub fn object_identifier(arcs: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    base128(&mut out, folded(arcs));
    for arc in arcs.iter().skip(2) {
        base128(&mut out, u64::from(*arc));
    }
    out
}

fn base128(out: &mut Vec<u8>, mut arc: u64) {
    let mut stack = [0u8; 10];
    let mut count = 0;
    loop {
        stack[count] = u8::try_from(arc & 0x7f).unwrap_or(0);
        count += 1;
        arc >>= 7;
        if arc == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        let more = if index == 0 { 0 } else { 0x80 };
        out.push(stack[index] | more);
    }
}

/// The arcs an `OBJECT IDENTIFIER`'s contents encode.
///
/// # Errors
///
/// Empty contents, an arc larger than 32 bits, or a last arc that does not
/// end.
pub fn read_object_identifier(contents: &[u8]) -> Result<Vec<u32>> {
    if contents.is_empty() {
        return Err(Asn1Error::new("an empty OBJECT IDENTIFIER"));
    }
    let mut arcs = Vec::new();
    let mut arc: u32 = 0;
    let mut starts = true;
    for byte in contents {
        if starts && *byte == 0x80 {
            return Err(Asn1Error::new(
                "an OBJECT IDENTIFIER arc padded with a leading 0x80 (X.690 8.19.2)",
            ));
        }
        starts = byte & 0x80 == 0;
        if arc >= (1 << 25) {
            return Err(Asn1Error::new(
                "an OBJECT IDENTIFIER arc larger than 32 bits",
            ));
        }
        arc = (arc << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if arcs.is_empty() {
                let (first, second) = if arc < 80 {
                    (arc / 40, arc % 40)
                } else {
                    (2, arc - 80)
                };
                arcs.push(first);
                arcs.push(second);
            } else {
                arcs.push(arc);
            }
            arc = 0;
        }
    }
    if contents.last().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(Asn1Error::new("an OBJECT IDENTIFIER arc that does not end"));
    }
    Ok(arcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arcs_round_trip_and_the_first_two_fold_into_one() {
        for arcs in [
            vec![1, 3, 6, 1, 4, 1, 9, 9, 1, 0, 70_000],
            vec![2, 999, 3],
            vec![1, 2, 840, 113_549],
        ] {
            let contents = object_identifier(&arcs);
            assert_eq!(read_object_identifier(&contents).expect("read"), arcs);
        }
        assert_eq!(object_identifier(&[1, 3, 6, 1]), [0x2b, 6, 1]);
        assert_eq!(object_identifier(&[2, 5, 29, 74]), [0x55, 0x1d, 0x4a]);
    }

    #[test]
    fn arcs_that_fold_past_32_bits_or_name_no_root_are_refused() {
        // `first * 40 + second` in 32 bits overflowed here: a panic in a
        // debug build, a wrapped and wrong identifier in a release one.
        let past = object_identifier(&[2, u32::MAX]);
        assert_eq!(past.len(), 5, "folded in 64 bits");
        assert!(
            read_object_identifier(&past).is_err(),
            "and refused read back"
        );
        for text in ["2.4294967295", "2.4294967216", "3.0", "1.40", "0.40.1"] {
            assert_eq!(read_dotted(text), None, "{text}");
        }
        let largest = read_dotted("2.4294967215").expect("fits 32 bits");
        assert_eq!(
            read_object_identifier(&object_identifier(&largest)).expect("read"),
            largest
        );
        let padded = read_object_identifier(&[0x2b, 0x80, 0x01]).expect_err("padded");
        assert!(
            padded.message.contains("leading 0x80"),
            "{}",
            padded.message
        );
    }

    #[test]
    fn the_dotted_text_reads_back_as_its_arcs() {
        assert_eq!(dotted(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), "1.3.6.1.2.1.1.3.0");
        assert_eq!(dotted(&[]), "");
        assert_eq!(read_dotted(".1.3.6"), Some(vec![1, 3, 6]));
        assert_eq!(read_dotted("1.3.6"), Some(vec![1, 3, 6]));
        assert_eq!(read_dotted("1.x"), None);
        assert_eq!(read_dotted("1..3"), None);
        assert_eq!(read_dotted("4294967296"), None, "over 32 bits");
    }

    #[test]
    fn what_is_not_an_identifier_is_refused_saying_why() {
        let refused = |contents: &[u8]| read_object_identifier(contents).expect_err("refused");
        assert!(refused(&[]).message.contains("empty"));
        assert!(refused(&[0x81]).message.contains("does not end"));
        assert!(
            refused(&[0x2b, 0xff, 0xff, 0xff, 0xff, 0x7f])
                .message
                .contains("32 bits")
        );
    }
}
