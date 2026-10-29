# The test key — published on purpose, protects nothing

`bootsig-TEST-KEY.secret` and `bootsig-TEST-KEY.public` are an SLH-DSA-SHA2-128s
key pair made by `bootsign keygen --test` on 2026-10-29, key id
`a6c913d8a0e2476e`. **The secret half is public.** Anyone can sign anything with
it, so a boot it verified is a boot anyone could have made. That is its purpose:
the test lanes and CI need a key, and a key nobody has to guard is the only kind
a repository can hold. It is the snakeoil precedent RFC 0091 names: Ubuntu ships
OVMF's test key beside the firmware that trusts it.

So it is **named as a test key wherever it appears**:
- in these file names;
- in `bootsign`'s output, in red;
- and, from RFC 0091 step 3, in the boot report.

The release recipe refuses to build a loader that trusts it (step 5).

**A real key never lives here.** `bootsign keygen` without `--test` writes to
`$BHASKIX_KEYS`, by default `~/.bhaskix-keys/`, and refuses any directory inside
a git work tree (RFC 0091, question 7).
