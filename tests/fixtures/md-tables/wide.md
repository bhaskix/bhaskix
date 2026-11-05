<!-- SPDX-License-Identifier: Apache-2.0 -->

# A table the table check must refuse, once

`tools/check-md-tables.py` must name line 11 and nothing else here. Line 10 is
its control: the same command with the pipe escaped, which is two cells.

| command | what it does |
|---|---|
| `make test \| grep -c ok` | escaped: two cells, accepted |
| `make test | grep -c ok` | unescaped: three cells under two columns, refused |

After a blank line this is a paragraph, | with | pipes | in it |, which GitHub
shows whole, so the check has nothing to say about it.

```
| a fenced | table |
|---|---|
| is code | and not | a table |
```
