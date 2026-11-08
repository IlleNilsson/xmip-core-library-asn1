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

Two readers, one implementation that differs only in the length it takes.
The crate's own `read`, `expect`, `read_all` and `read_element` read DER, for
X.509, signatures and anything hashed or signed; `ber::read`, `ber::expect`,
`ber::read_all` and `ber::read_element` read BER, for the protocols that speak
it — LDAP (Active Directory writes every length as `0x84` and four bytes),
SNMP, MMS and GOOSE — and take a definite length in any form: a long form
under 128, and zero bytes in front of it. Both refuse the indefinite form and
a length over four bytes, and both hold an `INTEGER` to its fewest bytes, as
X.690 8.3.2 has it for both.

The DER reader is strict, so one value has one encoding and nothing rides
after it: a length in the long form under 128 or with a zero first byte, an
`INTEGER` padded with a byte its sign does not need, an `OBJECT IDENTIFIER`
arc padded with `0x80`, and an explicitly tagged field holding bytes after
its one element are each refused. `object_identifier` folds the first two arcs
in 64 bits, so no arcs overflow it, and `read_dotted` refuses a first arc
other than 0, 1 or 2, a second over 39 under 0 or 1, and two arcs that fold
past the 32 bits the reader takes back, so every identifier read from text is
written and read back as itself.

The content encodings of the universal types every protocol shares are here
too: an `INTEGER`'s two's complement, read once and taken signed
(`read_integer`) or unsigned (`read_unsigned`, which `Element::integer` and
SNMP's counters and gauges read through) and written either way (`integer`,
`unsigned`); and an `OBJECT IDENTIFIER`'s arcs, as contents and as the
dotted text X.660 writes them in (`dotted`, `read_dotted`). SNMP carried the
only copy of the identifier until 2026-09-24, and its dotted text, the
unsigned reader and writer until 2026-09-28, when this crate also read a
32-bit `INTEGER` a second way.

What a `GeneralString` or a `GeneralizedTime` means to Kerberos — UTF-8
text, and whole seconds in UTC only — is Kerberos's, in
`xmip-core-identify` (`identify::kerberos`); it sat here until 2026-09-28.
The crate depends on nothing.

`architecture.xmip` carries the maturity.
