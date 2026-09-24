//! The contents of an `OBJECT IDENTIFIER` (X.690 8.19): the first two arcs
//! folded into one as `40 * first + second`, then every arc in base 128,
//! the high bit set on every byte but an arc's last.
//!
//! Here beside [`crate::integer`] because it is a universal type's content
//! encoding, which no protocol owns: SNMP carried the only copy until
//! 2026-09-24. How a protocol spells an identifier as text is its own.

use crate::{Asn1Error, Result};

/// The contents that encode `arcs`. An identifier of fewer than two arcs is
/// written as though the missing ones were zero.
#[must_use]
pub fn object_identifier(arcs: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let first = arcs.first().copied().unwrap_or(0) * 40 + arcs.get(1).copied().unwrap_or(0);
    base128(&mut out, first);
    for arc in arcs.iter().skip(2) {
        base128(&mut out, *arc);
    }
    out
}

fn base128(out: &mut Vec<u8>, mut arc: u32) {
    let mut stack = [0u8; 5];
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
    for byte in contents {
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
