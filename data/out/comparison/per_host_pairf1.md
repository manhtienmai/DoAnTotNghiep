# So sánh Pair-F1 theo Host × Phương pháp

> delta=0.5, threshold=0.3, repeats=1, alpha=0.5 (LCS+Jaccard), epsilon=0.01 (Sinkhorn OT). Mean ± SD tính qua 4 host.

| Host | #groups | Baseline Pair-F1 | LCS+Jaccard | Sinkhorn OT | Combined |
|---|---|---|---|---|---|
| cup | 125 | 0.1855 | 0.1924 | 0.2074 | 0.2006 |
| spiral | 919 | 0.7054 | 0.7054 | 0.5152 | 0.8302 |
| onion | 19 | 0.3288 | 0.3288 | 0.3514 | 0.3514 |
| insect | 885 | 0.3093 | 0.3162 | 0.3758 | 0.3759 |
| Mean ± SD | — | 0.3822 ± 0.2246 | 0.3857 ± 0.2218 | 0.3624 ± 0.1260 | 0.4395 ± 0.2717 |
