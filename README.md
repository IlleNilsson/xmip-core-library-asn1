# xmip-core-library-asn1

X.690, the tag-length-value every ASN.1 protocol and token frames with, read
and written: a one-byte tag, a definite length in short or long form, the
contents. The basic encoding rules and the distinguished ones differ in what a
writer may choose, and this writes the one form both accept.

SNMP, MMS and GOOSE reach it through the transport capability; LDAP, Kerberos
and X.509 through authentication and identification. Until 2026-09-22 six of
them carried a reader of their own. Nothing here knows what a tag means — that
stays with the protocol that says it.

Deliberately a subset: the high-tag-number form and the indefinite length are
refused, a length is at most four bytes wide, and nothing is copied — an
`Element` borrows its contents from the bytes it was read out of.

`architecture.toml` carries the maturity.
