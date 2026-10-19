<!-- SPDX-License-Identifier: Apache-2.0 -->

# A guide that is wrong five ways

`tools/check-guides.py --only` must refuse this file, and name all five faults.
`make gates` counts them.

It names a command the user-mode shell does not have, as the README did until
2026-10-19:

```
bhaskix$ help
bhaskix$ ps
```

a `pkg` verb that does not exist:

```
bhaskix$ pkg erase hello
```

a command the kernel shell does not have:

```
bhaskix> top
```

and a link that [leads nowhere](no-such-guide.md). It also carries no line
saying when it was verified.
