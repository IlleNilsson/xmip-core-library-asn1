//! The basic encoding rules' reading, for the protocols that speak BER:
//! LDAP, whose Active Directory writes every length as `0x84` and four
//! bytes; SNMP; MMS and GOOSE. The same reader as the crate's own, which
//! reads DER for X.509, signatures and anything hashed or signed; it differs
//! only in the length it takes: any definite form, a long form under 128
//! and zero bytes in front of it included. The indefinite form and a length
//! over four bytes are refused as there, each element is held to the bytes
//! it is read from, and an `INTEGER` is read as X.690 8.3.2 has it in both
//! rules, in the fewest bytes.

use std::io::Read;

use crate::Result;
use crate::decode::{Rules, expect_by, read_all_by, read_by, read_element_by};

/// The first element of `bytes`, by BER: as [`crate::read`] but for the
/// length.
///
/// # Errors
/// As [`crate::read`], a longer length than needed excepted.
pub fn read(bytes: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    read_by(bytes, Rules::Ber)
}

/// The first element of `bytes`, which must carry `tag`, by BER.
///
/// # Errors
/// As [`read`], or the element carries another tag.
pub fn expect(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    expect_by(bytes, tag, Rules::Ber)
}

/// Every element of `bytes`, in order, by BER.
///
/// # Errors
/// As [`read`], for any of them.
pub fn read_all(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    read_all_by(bytes, Rules::Ber)
}

/// One whole element off a stream, by BER, of at most `largest` bytes of
/// contents.
///
/// # Errors
/// As [`crate::read_element`], a longer length than needed excepted.
pub fn read_element(stream: &mut impl Read, largest: usize) -> Result<Vec<u8>> {
    read_element_by(stream, largest, Rules::Ber)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OCTET_STRING, SEQUENCE};

    #[test]
    fn an_0x84_length_is_ber_and_not_der() {
        // How Active Directory frames an LDAPMessage: four length bytes.
        let written = [SEQUENCE, 0x84, 0, 0, 0, 3, OCTET_STRING, 1, b'x'];
        let (tag, contents, rest) = read(&written).expect("BER takes it");
        assert_eq!((tag, contents, rest), (SEQUENCE, &written[6..], &[][..]));
        assert_eq!(
            read_all(contents).expect("inside"),
            [(OCTET_STRING, &b"x"[..])]
        );
        assert_eq!(expect(&written, SEQUENCE).expect("tagged").0, &written[6..]);
        let refused = crate::read(&written).expect_err("DER refuses it");
        assert!(refused.message.contains("zero byte"), "{}", refused.message);

        let mut stream = &written[..];
        assert_eq!(
            read_element(&mut stream, 16).expect("off a stream"),
            written
        );
        assert!(crate::read_element(&mut &written[..], 16).is_err());
    }

    #[test]
    fn ber_still_refuses_what_has_no_definite_bounded_length() {
        assert!(read(&[SEQUENCE, 0x80, 0, 0]).is_err(), "indefinite");
        assert!(
            read(&[SEQUENCE, 0x85, 0, 0, 0, 0, 1, 0]).is_err(),
            "five bytes"
        );
        assert!(
            read(&[SEQUENCE, 0x84, 0, 0, 0, 9, 1]).is_err(),
            "past the end"
        );
        let mut huge: &[u8] = &[SEQUENCE, 0x84, 0x7f, 0xff, 0xff, 0xff];
        assert!(
            read_element(&mut huge, 1024).is_err(),
            "over the caller's bound"
        );
        assert_eq!(
            read(&[OCTET_STRING, 0x81, 1, b'y']).expect("long form").1,
            b"y"
        );
    }
}
