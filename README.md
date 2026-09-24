# xmip-core-library-asn1

X.690, the tag-length-value every ASN.1 protocol and token frames with, read
and written: a one-byte tag, a definite length in short or long form, the
contents. The basic encoding rules and the distinguished ones differ in what a
writer may choose, and this writes the one form both accept.

SNMP, MMS and GOOSE, LDAP, Kerberos and X.509 each depend on it directly; no
capability re-exports it. Until 2026-09-22 six of
them carried a reader of their own. Nothing here knows what a tag means — that
stays with the protocol that says it.

Deliberately a subset: the high-tag-number form and the indefinite length are
refused, a length is at most four bytes wide, and nothing is copied — an
`Element` borrows its contents from the bytes it was read out of.

The content encodings of the universal types every protocol shares are here
too: an `INTEGER`'s two's complement and an `OBJECT IDENTIFIER`'s arcs,
which SNMP carried the only copy of until 2026-09-24. How a protocol spells
an identifier as text stays with the protocol.

A `GeneralizedTime` is read into seconds since the epoch through
`xmip-core-library-codec`'s civil calendar, the estate's one; until 2026-09-24
this crate and the SAML gate each carried the arithmetic.

`architecture.toml` carries the maturity.
