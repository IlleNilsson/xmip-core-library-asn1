#![forbid(unsafe_code)]

//! X.690 tag-length-value: what every ASN.1 protocol and token frames with.
//!
//! ```text
//! tag     one byte: class, constructed, number under 31
//! length  under 128 in one byte; else 0x80 | n, then n bytes, n at most 4
//! value   that many bytes
//! ```
//!
//! SNMP, MMS and GOOSE on the transport side, LDAP, Kerberos and X.509 on the
//! authentication side each carried this reader until 2026-09-22, six copies
//! of one subset with six sets of error messages. The subset is kept:
//! the high-tag-number form and the indefinite length are refused, which no
//! protocol Xmip speaks needs, and a writer here always uses the shortest
//! definite length, which is DER and is also valid BER.
//!
//! Nothing here knows what a tag means. [`Element`] reads the explicitly
//! tagged fields Kerberos and SPNEGO are made of; the flat functions read and
//! write for protocols that walk their own structure.
//!
//! A capability turns an [`Asn1Error`] into its own error with `From`, so a
//! technology writes `?` and the reason travels unchanged.

mod decode;
mod element;
mod encode;
mod oid;

pub use decode::{expect, find, read, read_all, read_element, read_integer};
pub use element::Element;
pub use encode::{integer, tlv, write_tlv};
pub use oid::{object_identifier, read_object_identifier};

/// `BOOLEAN`.
pub const BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub const BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// `NULL`.
pub const NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`.
pub const OBJECT_IDENTIFIER: u8 = 0x06;
/// `ENUMERATED`: an LDAP result code.
pub const ENUMERATED: u8 = 0x0a;
/// `GeneralizedTime`, which RFC 4120 uses for every time.
pub const GENERALIZED_TIME: u8 = 0x18;
/// `VisibleString`.
pub const VISIBLE_STRING: u8 = 0x1a;
/// `GeneralString`, which RFC 4120 uses for every name.
pub const GENERAL_STRING: u8 = 0x1b;
/// `SEQUENCE` and `SEQUENCE OF`, constructed.
pub const SEQUENCE: u8 = 0x30;

/// The tag of `[n]`, context-specific, constructed or primitive.
#[must_use]
pub const fn context(number: u8, constructed: bool) -> u8 {
    0x80 | if constructed { 0x20 } else { 0x00 } | (number & 0x1f)
}

/// The tag of `[APPLICATION n]`, constructed.
#[must_use]
pub const fn application(number: u8) -> u8 {
    0x60 | (number & 0x1f)
}

/// Why bytes are not the X.690 this reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Error {
    /// What was wrong, in words.
    pub message: String,
}

impl Asn1Error {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for Asn1Error {}

/// The result of reading X.690.
pub type Result<T> = core::result::Result<T, Asn1Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_and_application_tags_carry_class_form_and_number() {
        assert_eq!(context(5, true), 0xa5);
        assert_eq!(context(9, false), 0x89);
        assert_eq!(application(0), 0x60);
        assert_eq!(application(14), 0x6e);
    }
}
