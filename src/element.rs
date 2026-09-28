//! One element as a value, for structures of explicitly tagged fields.
//!
//! Kerberos and SPNEGO are `SEQUENCE`s whose fields are each wrapped in
//! `[n]`; [`Element::field`] finds and unwraps one. Nothing is copied: an
//! element borrows its contents from the bytes it was read out of. What a
//! `GeneralString` or a `GeneralizedTime` means to Kerberos is Kerberos's
//! (`identify::kerberos`), not this reader's.

use crate::{Asn1Error, INTEGER, Result, context};

/// One element: its tag and its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    /// The tag byte.
    pub tag: u8,
    /// The contents.
    pub content: &'a [u8],
}

impl<'a> Element<'a> {
    /// The element at the head of `input`, and what follows it.
    ///
    /// # Errors
    /// As [`crate::read`].
    pub fn read(input: &'a [u8]) -> Result<(Self, &'a [u8])> {
        let (tag, content, rest) = crate::read(input)?;
        Ok((Self { tag, content }, rest))
    }

    /// The element at the head of `input`, which must carry `tag`.
    ///
    /// # Errors
    /// As [`Element::read`], and where the tag is another: the error names
    /// `what` was expected.
    pub fn expect(input: &'a [u8], tag: u8, what: &str) -> Result<Self> {
        let (element, _) = Self::read(input)?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(Asn1Error::new(format!(
                "expected {what} (tag {tag:#04x}) and found tag {:#04x}",
                element.tag
            )))
        }
    }

    /// The elements inside this one, in order.
    ///
    /// # Errors
    /// As [`Element::read`], for any of them.
    pub fn children(&self) -> Result<Vec<Element<'a>>> {
        let mut children = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (child, after) = Self::read(rest)?;
            children.push(child);
            rest = after;
        }
        Ok(children)
    }

    /// What `[number]`, explicitly tagged, wraps among this element's
    /// children, where it is there.
    ///
    /// # Errors
    /// As [`Element::read`].
    pub fn field(&self, number: u8) -> Result<Option<Element<'a>>> {
        self.children()?
            .into_iter()
            .find(|child| child.tag == context(number, true))
            .map(|wrapper| Self::read(wrapper.content).map(|(inner, _)| inner))
            .transpose()
    }

    /// The contents as a non-negative `INTEGER` that fits 32 bits, read by
    /// [`crate::read_unsigned`].
    #[must_use]
    pub fn integer(&self) -> Option<u32> {
        if self.tag != INTEGER {
            return None;
        }
        crate::read_unsigned(self.content)
            .ok()
            .and_then(|value| u32::try_from(value).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OCTET_STRING, SEQUENCE, tlv};

    #[test]
    fn a_long_form_length_is_read_and_a_truncated_element_is_refused() {
        let element = tlv(OCTET_STRING, &[7; 300]);

        let (read, rest) = Element::read(&element).expect("read");
        let failure = Element::read(&element[..100]).expect_err("truncated");

        assert_eq!(
            (read.tag, read.content.len(), rest.len()),
            (OCTET_STRING, 300, 0)
        );
        assert!(
            failure.message.contains("ends inside"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn a_tagged_field_is_found_among_its_siblings_and_unwrapped() {
        let fields = [
            tlv(context(0, true), &tlv(INTEGER, &[5])),
            tlv(context(1, true), &tlv(OCTET_STRING, b"HTTP")),
        ]
        .concat();
        let sequence = tlv(SEQUENCE, &fields);
        let (element, _) = Element::read(&sequence).expect("read");

        assert_eq!(
            element.field(0).expect("read").and_then(|e| e.integer()),
            Some(5)
        );
        assert_eq!(
            element.field(1).expect("read").map(|e| e.content),
            Some(&b"HTTP"[..])
        );
        assert_eq!(element.field(3).expect("read"), None);
    }

    #[test]
    fn an_unexpected_tag_names_what_was_expected() {
        let failure =
            Element::expect(&tlv(OCTET_STRING, &[]), SEQUENCE, "a Ticket").expect_err("mistagged");
        assert!(
            failure.message.contains("expected a Ticket"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn an_integer_is_read_only_where_it_is_non_negative_and_fits() {
        let at = |content: &[u8]| {
            Element {
                tag: INTEGER,
                content,
            }
            .integer()
        };
        assert_eq!(at(&[0x00, 0xff, 0xff, 0xff, 0xff]), Some(u32::MAX));
        assert_eq!(at(&[0x80]), None);
        assert_eq!(at(&[1, 0, 0, 0, 0]), None);
        assert_eq!(
            Element {
                tag: OCTET_STRING,
                content: &[1]
            }
            .integer(),
            None
        );
    }
}
