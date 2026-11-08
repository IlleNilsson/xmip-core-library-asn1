//! Reading: the element at the head of some bytes, or off a stream, by
//! the distinguished rules here and by the basic ones in [`crate::ber`],
//! one reader for both that differs only in the length it takes.

use std::io::Read;

use crate::{Asn1Error, Result};

/// Which of X.690's encoding rules a length is read by.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Rules {
    /// The distinguished rules: one length for one value, the shortest.
    Der,
    /// The basic rules: a definite length in any form, a long form under
    /// 128 and zero bytes in front of it included.
    Ber,
}

/// The first element of `bytes`: its tag, its contents, and what follows.
///
/// # Errors
/// Nothing there, cut short, a tag of the high-tag-number form, or a length
/// that is indefinite, wider than four bytes, past the end, or not the
/// shortest DER writes (X.690 10.1): a long form under 128, or a zero first
/// byte.
pub fn read(bytes: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    read_by(bytes, Rules::Der)
}

/// [`read`] by `rules`.
pub(crate) fn read_by(bytes: &[u8], rules: Rules) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = bytes
        .split_first()
        .ok_or_else(|| Asn1Error::new("an element was expected and there is none"))?;
    if tag & 0x1f == 0x1f {
        return Err(Asn1Error::new(
            "an element's tag is of the high-tag-number form, which no protocol here uses",
        ));
    }
    let (length, took) = length(after_tag, rules)?;
    let rest = &after_tag[took..];
    let (contents, rest) = rest.split_at_checked(length).ok_or_else(|| {
        Asn1Error::new(format!(
            "an element ends inside its contents: it says {length} bytes and {} follow",
            rest.len()
        ))
    })?;
    Ok((tag, contents, rest))
}

/// The definite length at the head of `bytes`: what it says, and how many
/// bytes saying so took. Both rules refuse the indefinite form and more
/// than four bytes of it; only DER refuses one longer than it needs.
fn length(bytes: &[u8], rules: Rules) -> Result<(usize, usize)> {
    let &first = bytes
        .first()
        .ok_or_else(|| Asn1Error::new("an element ends before its length"))?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let width = usize::from(first & 0x7f);
    if width == 0 || width > 4 {
        return Err(Asn1Error::new(
            "an element's length is indefinite or wider than four bytes",
        ));
    }
    let digits = bytes
        .get(1..=width)
        .ok_or_else(|| Asn1Error::new("an element ends inside its length"))?;
    if rules == Rules::Der && digits[0] == 0 {
        return Err(Asn1Error::new(
            "an element's length starts with a zero byte, which DER writes shorter",
        ));
    }
    let said = digits
        .iter()
        .fold(0usize, |sum, &digit| (sum << 8) | usize::from(digit));
    if rules == Rules::Der && said < 0x80 {
        return Err(Asn1Error::new(format!(
            "an element's length {said} is in the long form, which DER writes in one byte"
        )));
    }
    Ok((said, 1 + width))
}

/// The first element of `bytes`, which must carry `tag`: its contents and
/// what follows.
///
/// # Errors
/// As [`read`], or the element carries another tag.
pub fn expect(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    expect_by(bytes, tag, Rules::Der)
}

/// [`expect`] by `rules`.
pub(crate) fn expect_by(bytes: &[u8], tag: u8, rules: Rules) -> Result<(&[u8], &[u8])> {
    let (found, contents, rest) = read_by(bytes, rules)?;
    if found != tag {
        return Err(Asn1Error::new(format!(
            "an element tagged {tag:#04x} was expected and {found:#04x} arrived"
        )));
    }
    Ok((contents, rest))
}

/// Every element of `bytes`, in order, as tag and contents.
///
/// # Errors
/// As [`read`], for any of them.
pub fn read_all(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    read_all_by(bytes, Rules::Der)
}

/// [`read_all`] by `rules`.
pub(crate) fn read_all_by(mut bytes: &[u8], rules: Rules) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tag, contents, rest) = read_by(bytes, rules)?;
        out.push((tag, contents));
        bytes = rest;
    }
    Ok(out)
}

/// The contents of the element in `elements` tagged `tag`.
///
/// # Errors
/// No such element.
pub fn find<'a>(elements: &[(u8, &'a [u8])], tag: u8) -> Result<&'a [u8]> {
    elements
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, contents)| *contents)
        .ok_or_else(|| Asn1Error::new(format!("no element tagged {tag:#04x}")))
}

/// The value an `INTEGER`'s contents carry, signed.
///
/// # Errors
/// Empty, or wider than eight bytes.
pub fn read_integer(contents: &[u8]) -> Result<i64> {
    if contents.len() > 8 {
        return Err(Asn1Error::new(format!(
            "an INTEGER of {} bytes, where one to eight are read signed",
            contents.len()
        )));
    }
    i64::try_from(twos_complement(contents)?).map_err(|_| {
        Asn1Error::new("an INTEGER outside what sixty-four bits hold, where a signed one is read")
    })
}

/// The value an `INTEGER`'s contents carry where it may not be negative: a
/// counter, a gauge, a version, an encryption type — one to nine bytes, the
/// ninth only the zero that keeps the top bit from reading as a sign.
///
/// # Errors
/// Empty, negative, or wider than sixty-four bits.
pub fn read_unsigned(contents: &[u8]) -> Result<u64> {
    u64::try_from(twos_complement(contents)?).map_err(|_| {
        Asn1Error::new(
            "an INTEGER that is negative or wider than sixty-four bits, where an \
                        unsigned one is read",
        )
    })
}

/// The two's complement `contents` spell, the one reading of an
/// `INTEGER`'s contents the typed readers above take their range from;
/// a first byte its sign does not need is refused (X.690 8.3.2).
fn twos_complement(contents: &[u8]) -> Result<i128> {
    if contents.is_empty() || contents.len() > 9 {
        return Err(Asn1Error::new(format!(
            "an INTEGER of {} bytes, where one to nine are read",
            contents.len()
        )));
    }
    if let [first, second, ..] = contents
        && ((*first == 0x00 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0))
    {
        return Err(Asn1Error::new(
            "an INTEGER padded with a byte its sign does not need, which DER writes shorter",
        ));
    }
    let mut value: i128 = if contents[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in contents {
        value = (value << 8) | i128::from(byte);
    }
    Ok(value)
}

/// One whole element off a stream, tag and length included, where it says
/// no more than `largest` bytes of contents: the bound is the caller's,
/// because only the protocol knows how large an answer can honestly be.
///
/// # Errors
/// The stream ends or fails first, the length is not one [`read`] reads, or
/// the element is larger than `largest`.
pub fn read_element(stream: &mut impl Read, largest: usize) -> Result<Vec<u8>> {
    read_element_by(stream, largest, Rules::Der)
}

/// [`read_element`] by `rules`.
pub(crate) fn read_element_by(
    stream: &mut impl Read,
    largest: usize,
    rules: Rules,
) -> Result<Vec<u8>> {
    let cut = |failure: std::io::Error| {
        Asn1Error::new(format!("an element was cut short on the stream: {failure}"))
    };
    let mut element = vec![0u8; 2];
    stream.read_exact(&mut element).map_err(cut)?;
    if element[1] >= 0x80 {
        let width = usize::from(element[1] & 0x7f);
        let mut more = vec![0u8; width.min(4)];
        stream.read_exact(&mut more).map_err(cut)?;
        element.extend_from_slice(&more);
    }
    let (said, _) = length(&element[1..], rules)?;
    if said > largest {
        return Err(Asn1Error::new(format!(
            "an element says {said} bytes, more than the {largest} this reads"
        )));
    }
    let header = element.len();
    element.resize(header + said, 0);
    stream.read_exact(&mut element[header..]).map_err(cut)?;
    Ok(element)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{INTEGER, NULL, OCTET_STRING, SEQUENCE, tlv};

    #[test]
    fn elements_are_read_in_order_and_found_by_tag() {
        let long = tlv(OCTET_STRING, &[7; 300]);
        let (tag, contents, rest) = read(&long).expect("read");
        assert_eq!((tag, contents.len(), rest.len()), (OCTET_STRING, 300, 0));

        let two = [tlv(OCTET_STRING, b"hi"), tlv(NULL, &[])].concat();
        let all = read_all(&two).expect("all");
        assert_eq!(all, vec![(OCTET_STRING, &b"hi"[..]), (NULL, &[][..])]);
        assert_eq!(find(&all, NULL).expect("null"), &[]);
        assert!(find(&all, INTEGER).is_err());
        assert_eq!(expect(&two, OCTET_STRING).expect("hi").0, b"hi");
    }

    #[test]
    fn what_is_not_this_subset_of_x690_is_refused_saying_why() {
        let refused = |bytes: &[u8]| read(bytes).expect_err("refused").message;
        assert!(refused(&[]).contains("there is none"));
        assert!(refused(&[0x04]).contains("before its length"));
        assert!(refused(&[0x1f, 0x01, 0x00]).contains("high-tag-number"));
        assert!(refused(&[0x30, 0x80, 0, 0]).contains("indefinite"));
        assert!(refused(&[0x04, 0x85, 0, 0, 0, 0, 0]).contains("wider than four"));
        assert!(refused(&[0x04, 0x82, 0x01]).contains("inside its length"));
        assert!(refused(&[0x04, 0x05, 1, 2]).contains("says 5 bytes and 2 follow"));

        let mistagged = expect(&[0x04, 0x00], INTEGER).expect_err("mistagged");
        assert!(mistagged.message.contains("0x02"), "{}", mistagged.message);
        assert!(read_integer(&[]).is_err());
        assert!(read_integer(&[0; 9]).is_err(), "nine bytes signed");
        assert!(
            read_integer(&[0x00, 0x80, 0, 0, 0, 0, 0, 0, 0]).is_err(),
            "2^63"
        );
    }

    #[test]
    fn a_length_or_integer_that_der_writes_shorter_is_refused() {
        let refused = |bytes: &[u8]| read(bytes).expect_err("refused").message;
        assert!(refused(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).contains("long form"));
        assert!(refused(&[0x04, 0x82, 0x00, 0x05, 1, 2, 3, 4, 5]).contains("zero byte"));
        let mut stream: &[u8] = &[0x04, 0x84, 0, 0, 0, 1, 7];
        assert!(read_element(&mut stream, 16).is_err(), "padded on a stream");
        assert!(
            read(&tlv(OCTET_STRING, &[7; 128])).is_ok(),
            "128 is long form"
        );
        for padded in [&[0x00, 0x05][..], &[0xff, 0xff], &[0x00, 0x00, 0x80]] {
            let message = read_integer(padded).expect_err("padded").message;
            assert!(message.contains("does not need"), "{message}");
            assert!(read_unsigned(padded).is_err());
        }
        assert_eq!(read_integer(&[0xff, 0x7f]).expect("minimal"), -129);
        assert_eq!(read_integer(&[0x00]).expect("zero"), 0);
    }

    #[test]
    fn an_integer_reads_signed_or_unsigned_from_one_reading_of_its_contents() {
        assert_eq!(read_integer(&[0xff, 0x7f]).expect("signed"), -129);
        assert_eq!(
            read_integer(&[0x80, 0, 0, 0, 0, 0, 0, 0]).expect("min"),
            i64::MIN
        );
        assert_eq!(read_unsigned(&[0x00, 0x80]).expect("unsigned"), 128);
        let max = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(read_unsigned(&max).expect("max"), u64::MAX);
        assert!(read_unsigned(&[0x80]).is_err(), "negative");
        assert!(read_unsigned(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(), "2^64");
        assert!(read_unsigned(&[]).is_err());
    }

    #[test]
    fn one_element_is_read_off_a_stream_and_the_next_is_left() {
        let mut wire = tlv(SEQUENCE, &[9u8; 200]);
        wire.extend_from_slice(&tlv(OCTET_STRING, b"next"));
        let mut stream = wire.as_slice();

        let first = read_element(&mut stream, 1024).expect("read");
        assert_eq!(first, tlv(SEQUENCE, &[9u8; 200]));
        assert_eq!(
            read_element(&mut stream, 1024).expect("read"),
            tlv(OCTET_STRING, b"next")
        );
        assert!(read_element(&mut stream, 1024).is_err());

        let mut huge: &[u8] = &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff];
        let failure = read_element(&mut huge, 1024).expect_err("refused");
        assert!(
            failure.message.contains("more than the 1024"),
            "{}",
            failure.message
        );
    }
}
