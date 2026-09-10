# Model-results reconciliation across the three sources

Purpose: decide which numbers go into the paper's Table 7.10 (corrected corpus).
Three sources were compared: `notebook/benchmark_corrected_models.py/.ipynb`,
`notebook/Models.ipynb`, and `notebook/Lightgbm&XAI.ipynb`.

## The headline problem: the three sources do NOT measure the same thing

| Source | Corpus / test split | Feature set | Threshold | Cross-model consistency |
|---|---|---|---|---|
| **benchmark_corrected_models** | corrected, **301,661** test (one frozen split for every model) | **corrected 53-feature** | same target-recall policy for all | **consistent** — the only apples-to-apples comparison |
| Models.ipynb | **mixed** — some rows 301,661 (corrected), some **302,238 (OLD uncorrected)**, some 301,642 | simpler / per-model feature sets | per-model, not unified | **inconsistent** |
| Lightgbm&XAI.ipynb | corrected (cell 6, 301,661) and OLD (cells 4–5, 302,238) | corrected 53-feature (cell 6) | target-recall | LightGBM only |

`Models.ipynb`'s comparison table sums to different test totals per row (verified):
XGBoost/Ensemble = 301,661; **Single-Cell RF & LightGBM = 302,238 (old corpus)**;
GRU/Mamba/Transformer = 301,642. Its **Ensemble row is broken** (41,597 FP, F1 0.1665).
So it cannot be used as-is for the paper.

## Corrected-corpus results — authoritative source (benchmark_corrected_models)

All models, one 53-feature corrected split (test = 301,661), same target-recall policy.

| Model | FP | FN | Errors | F1 % | note |
|---|---:|---:|---:|---:|---|
| **LightGBM (retained headline, Fig 7.6)** | **8** | **2** | **10** | **99.9899** | τ=0.7337, from `train_corrected_canonical.py` |
| LightGBM (benchmark, uniform policy) | 7 | 3 | 10 | 99.99 | same model, adjacent plateau threshold |
| XGBoost | 10 | 5 | 15 | 99.985 | |
| Random Forest | 36 | 3 | 39 | 99.961 | |
| Mamba | 858 | 2 | 860 | 99.14 | pre-calibration run |
| Transformer | 2130 | 6 | 2136 | 97.90 | pre-calibration run |
| GRU | 4261 | 7 | 4268 | 95.88 | pre-calibration run |
| Weighted ensemble | 89 | 4 | 93 | 99.91 | includes the weak neural models |

**Verdict:** LightGBM is best on the corrected corpus (10 errors), XGBoost second (15),
RF third (39); the sequence models carry a large false-positive burden under the
recall target. This confirms the thesis's model choice on corrected data.

## Where the same model disagrees across sources (and why)

| Model | benchmark (corrected 53-feat) | Models.ipynb | Lightgbm&XAI (corrected) |
|---|---|---|---|
| LightGBM | 7 FP / 3 FN (10) | 12 FP / 11 FN — **OLD 302,238 split** | 9 FP / 2 FN (11, baseline ensemble) → 8 FP / 2 FN (10, retained) |
| XGBoost | 10 FP / 5 FN (15) | **518 FP / 151 FN** — weaker feature set | — |
| Random Forest | 36 FP / 3 FN (39) | 17 FP / 97 FN — OLD, single-cell features | — |
| GRU | 4261 FP | 1488 FP — different threshold | — |
| Mamba | 858 FP | 1266 FP | — |
| Transformer | 2130 FP | 1370 FP | — |
| Weighted ensemble | 89 FP / 4 FN (93) | **41,597 FP (broken, F1 0.1665)** | — |

Differences are explained by: (a) corpus (corrected vs old), (b) feature set
(53-feature vs simpler per-model sets — this is why Models.ipynb's XGBoost is 50×
worse), (c) threshold policy, and (d) a broken ensemble in Models.ipynb.

## Recommendation for the paper

1. **Populate Table 7.10 from `benchmark_corrected_models` only** — it is the single
   internally-consistent corrected comparison (one split, one feature set, one policy).
2. **Keep the LightGBM headline at 8 FP / 2 FN, F1 99.9899%** (Fig 7.6, τ=0.7337).
   The benchmark's 7 FP / 3 FN is the same model at the uniform policy — identical
   10-error total, adjacent plateau point.
3. **Do not cite `Models.ipynb`'s comparison table** — it mixes corpora/splits and has
   a broken ensemble. If it must be retained, it needs a full corrected re-run on one
   split (which the benchmark already provides).
4. **Re-run the improved benchmark notebook before finalising the neural rows** — the
   numbers above are the pre-calibration run; the updated notebook adds early stopping,
   isotonic calibration and an F1-optimal operating point, which lowers the sequence-model
   FP substantially and is the fairer figure to report.
