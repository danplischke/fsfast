### http

| workload | unit | fsfast | reference | fsf | native | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 943 (1,004) | 551 (553) |  | 2,339 (2,562) | 1.71x |  |
| W1 seq-read-open | MB/s | 2,473 (2,511) | 701 (741) |  |  | 3.53x |  |
| W2 seq-write | MB/s | 2,181 (2,333) | 1,944 (2,088) |  | 790 (1,018) | 1.12x |  |
| W3 small-read | ops/s | 26,405 (28,543) | 7,750 (8,321) |  |  | 3.41x |  |
| W4 small-write | ops/s | 2,050 (2,145) | 2,142 (2,165) |  |  | 0.96x |  |
| W5 metadata-info | ops/s | 6,428 (6,711) | 2,317 (2,386) |  |  | 2.77x |  |
| W5 metadata-ls | entries/s | 226,933 (228,184) | 256,719 (264,996) |  |  | 0.88x |  |
| W5 metadata-find | entries/s | 193,212 (218,714) | 197,991 (201,657) |  |  | 0.98x |  |
| W6 random-read | MB/s | 210 (213) | 292 (297) |  |  | 0.72x |  |
| W7 copy |  | n/a | n/a |  |  |  |  |
| W8 delete |  | n/a | n/a |  |  |  |  |

