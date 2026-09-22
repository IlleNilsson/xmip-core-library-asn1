//! Reading: the element at the head of some bytes, or off a stream.

use std::io::Read;

use crate::{Asn1Error, Result};

/// The first element of `bytes`: its tag, its contents, and what follows.
///
/// # Errors
/// Nothing there, cut short, a tag of the high-tag-number form, or a length
/// that is indefinite, wider than four bytes or past the end.
pub fn read(bytes: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = bytes
        .split_first()
        .ok_or_else(|| Asn1Error::new("an element was expected and there is none"))?;
    if tag & 0x1f == 0x1f {
        return Err(Asn1Error::new(
            "an element's tag is of the high-tag-number form, which no protocol here uses",
        ));
    }
    let (length, took) = length(after_tag)?;
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
/// bytes saying so took.
fn length(bytes: &[u8]) -> Result<(usize, usize)> {
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
    let said = digits
        .iter()
        .fold(0usize, |sum, &digit| (sum << 8) | usize::from(digit));
    Ok((said, 1 + width))
}

/// The first element of `bytes`, which must carry `tag`: its contents and
/// what follows.
///
/// # Errors
/// As [`read`], or the element carries another tag.
pub fn expect(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let (found, contents, rest) = read(bytes)?;
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
pub fn read_all(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tag, contents, rest) = read(bytes)?;
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

/// The value an `INTEGER`'s contents carry.
///
/// # Errors
/// Empty, or wider than sixty-four bits.
pub fn read_integer(contents: &[u8]) -> Result<i64> {
    if contents.is_empty() || contents.len() > 8 {
        return Err(Asn1Error::new(format!(
            "an INTEGER of {} bytes, where one to eight are read",
            contents.len()
        )));
    }
    let mut value: i64 = if contents[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in contents {
        value = (value << 8) | i64::from(byte);
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
    let (said, _) = length(&element[1..])?;
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
        assert!(read_integer(&[0; 9]).is_err());
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
