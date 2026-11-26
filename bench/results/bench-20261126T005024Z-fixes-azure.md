### azure

| workload | unit | fsfast | reference | fsf | fsfast / ref | fsfast / fsf |
|---|---|---|---|---|---|---|
| W1 seq-read | MB/s | 406 (473) | 224 (261) | 818 (886) | 1.81x | 0.50x |
| W1 seq-read-open | MB/s | 551 (582) | 318 (326) |  | 1.73x |  |
| W3 small-read | ops/s | 1,272 (1,391) | 259 (267) | 1,427 (1,482) | 4.92x | 0.89x |
| W4 small-write | ops/s | 751 (854) | 465 (481) | 600 (620) | 1.62x | 1.25x |
| W6 random-read | MB/s | 64.1 (65.6) | 30.7 (31.0) | 53.8 (60.1) | 2.09x | 1.19x |
| W7 copy | MB/s | 4,150 (4,362) | 1,618 (1,625) | 4,720 (4,798) | 2.57x | 0.88x |
| W8 delete | ops/s | 714 (737) | 184 (188) | 661 (675) | 3.87x | 1.08x |

