#!/usr/bin/env python
"""
Canonical corrected_44 pipeline — the 5-seed LightGBM ensemble WITH the three
retained cross-stream context features folded in:
    ctx_lower_stnum_next3, ctx_st_back_count_w20, ctx_st_threads_w20
Trains, evaluates at the 0.50 operating point, and writes the full artefact
set to notebook/artefacts_corrected/. Does NOT touch the shipped run.
"""
import os, sys, json, time, platform
import numpy as np, pandas as pd, joblib, lightgbm as lgb, sklearn, scipy
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_curve, auc, average_precision_score

ROOT = "notebook/artifacts/corrected_44"
OUT  = "notebook/artefacts_corrected"
os.makedirs(OUT, exist_ok=True)
base = joblib.load(os.path.join(ROOT, "ids_lgbm_ensemble_11_errors.joblib"))
NPZ  = next(os.path.join(ROOT, f) for f in os.listdir(ROOT) if f.endswith(".npz"))
z = np.load(NPZ, allow_pickle=True)
X, y, pubs = z["features"], z["labels"], z["publisher_id"]
names = list(z["feature_names"])
st = X[:, names.index("stNum")].astype(float)
sq = X[:, names.index("sqNum")].astype(float)
S  = pd.Series(st)

# --- the three retained deterministic context features ---
st_diff = np.diff(st, prepend=st[0])
ctx = {}
ctx["ctx_st_back_count_w20"] = pd.Series((st_diff < 0).astype(float)).rolling(20, min_periods=1).sum().values
ctx["ctx_st_threads_w20"]    = S.rolling(20, min_periods=1).apply(lambda a: len(np.unique(a)), raw=True).values
fwd = np.full(len(st), np.inf)
for k in (1, 2, 3):
    shf = np.full(len(st), np.inf); shf[:-k] = st[k:]; fwd = np.minimum(fwd, shf)
ctx["ctx_lower_stnum_next3"] = ((fwd < st) & np.isfinite(fwd)).astype(float)
ctx_names = ["ctx_lower_stnum_next3", "ctx_st_back_count_w20", "ctx_st_threads_w20"]

Xc = np.column_stack([X] + [ctx[n] for n in ctx_names])
allnames = names + ctx_names
csv_row = np.arange(len(y))          # original stream/CSV data-row index

# --- reproduce the corrected_44 split, carrying csv_row ---
Xa, Xte, ia, ite, ya, yte = train_test_split(Xc, csv_row, y, test_size=.30, random_state=42, stratify=y)
Xtr, Xva, itr, iva, ytr, yva = train_test_split(Xa, ia, ya, test_size=.20, random_state=42, stratify=ya)

qlo, qhi = base["q_lo_ms"], base["q_hi_ms"]
def guards(A):
    d = pd.DataFrame(A, columns=allnames); ms = d["time_delta"].values * 1000
    d["dt_in_baseline_flag"] = ((ms >= qlo) & (ms <= qhi)).astype(int)
    d["dt_below_baseline"]   = (ms < qlo).astype(int)
    d["dt_above_baseline"]   = (ms > qhi).astype(int)
    d["dt_in_pub_baseline_flag"] = 0; d["dt_above_pub_baseline"] = 0; d["dt_below_pub_baseline"] = 0
    return d
Dtr, Dva, Dte = guards(Xtr), guards(Xva), guards(Xte)
final = list(Dtr.columns)

mono = {"sq_frac_pos1": -1, "sqNum_consistency": -1, "stNum_consistency": -1,
        "dt_in_baseline_flag": -1, "dt_in_pub_baseline_flag": -1,
        "sq_backwards_flag": 1, "sq_jump_gt1_flag": 1, "sq_jump_mag": 1,
        "st_change_flag": 1, "st_change_without_cmd_flag": 1,
        "dt_above_baseline": 1, "dt_below_baseline": 1,
        "dt_above_pub_baseline": 1, "dt_below_pub_baseline": 1, "st_change_with_cmd_flag": -1,
        "ctx_lower_stnum_next3": 1, "ctx_st_back_count_w20": 1, "ctx_st_threads_w20": 1}
constraints = [mono.get(n, 0) for n in final]
scale = float((ytr == 0).sum() / (ytr == 1).sum())
seeds = [11, 29, 47, 83, 131]
models = []
for s in seeds:
    params = dict(objective="binary", metric="binary_logloss", boosting_type="gbdt",
                  num_leaves=79, min_data_in_leaf=25, max_depth=-1, learning_rate=.035,
                  feature_fraction=.94, bagging_fraction=.90, bagging_freq=3, lambda_l1=.02,
                  lambda_l2=.08, scale_pos_weight=scale, monotone_constraints=constraints,
                  verbose=-1, num_threads=-1, device="cpu", force_col_wise=True, seed=s,
                  feature_fraction_seed=s, bagging_seed=s, data_random_seed=s)
    tr = lgb.Dataset(Dtr[final].values, ytr, feature_name=final, free_raw_data=False)
    va = lgb.Dataset(Dva[final].values, yva, feature_name=final, reference=tr, free_raw_data=False)
    t = time.time(); m = lgb.train(params, tr, num_boost_round=800, valid_sets=[va],
                                   callbacks=[lgb.early_stopping(50, verbose=False)])
    models.append(m); print(f"seed={s} best={m.best_iteration} ({time.time()-t:.0f}s)", flush=True)

THR = 0.50
sc_te = np.mean([m.predict(Dte[final].values, num_iteration=m.best_iteration) for m in models], axis=0)
sc_va = np.mean([m.predict(Dva[final].values, num_iteration=m.best_iteration) for m in models], axis=0)
pred = (sc_te >= THR).astype(int)
tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
roc = auc(*roc_curve(yte, sc_te)[:2]); pr = average_precision_score(yte, sc_te)

# --- write artefact set ---
pd.DataFrame({"csv_row": ite, "y_true": yte, "y_score": sc_te}).to_csv(f"{OUT}/test_predictions.csv", index=False)
pd.DataFrame({"csv_row": iva, "y_true": yva, "y_score": sc_va}).to_csv(f"{OUT}/val_predictions.csv", index=False)
Dte_out = Dte[final].copy(); Dte_out.insert(0, "csv_row", ite)
Dte_out.to_csv(f"{OUT}/test_features.csv", index=False)
pd.DataFrame({"row_position": np.arange(len(ite)), "csv_row": ite,
              "stNum": st[ite].astype(int), "sqNum": sq[ite].astype(int),
              "y_true": yte}).to_csv(f"{OUT}/test_row_index.csv", index=False)
meta = dict(
    dataset=os.path.basename(NPZ), n_rows=int(len(y)), attack_frac=float(y.mean()),
    threshold=THR, operating_point="predefined 0.50 (comparable to shipped run)",
    confusion_matrix=dict(tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp), errors=int(fp+fn)),
    metrics=dict(precision=float(tp/(tp+fp)), recall=float(tp/(tp+fn)),
                 accuracy=float((tp+tn)/len(yte)), roc_auc=float(roc), pr_auc=float(pr)),
    seeds=seeds, q_lo_ms=float(qlo), q_hi_ms=float(qhi),
    context_features_added=ctx_names, feature_list=final, n_features=len(final),
    monotone_constraints=dict(zip(final, constraints)),
    split=dict(test_size=0.30, val_size_of_train=0.20, random_state=42, stratified=True),
    n_test=int(len(yte)), n_val=int(len(yva)), n_train=int(len(ytr)),
    library_versions=dict(python=platform.python_version(), numpy=np.__version__,
        pandas=pd.__version__, lightgbm=lgb.__version__, scikit_learn=sklearn.__version__,
        scipy=scipy.__version__),
    baseline_reference=dict(model="ids_lgbm_ensemble_11_errors.joblib", errors=11, note="2 FN + 9 FP"),
)
json.dump(meta, open(f"{OUT}/run_metadata.json", "w"), indent=2)
joblib.dump(dict(models=models, feature_names=final, ctx_names=ctx_names, q_lo_ms=qlo, q_hi_ms=qhi,
                 monotone_constraints=constraints, tuned_threshold=THR,
                 test_metrics=meta["confusion_matrix"]),
            f"{OUT}/ids_lgbm_ensemble_corrected.joblib")

print("\n" + "="*56)
print(f"RETAINED MODEL (corrected_44 + 3 context features) @ thr={THR}")
print(f"  CM = [[TN {tn}, FP {fp}], [FN {fn}, TP {tp}]]   errors={fp+fn}")
print(f"  recall={tp/(tp+fn):.6f}  precision={tp/(tp+fp):.6f}  roc_auc={roc:.7f}  pr_auc={pr:.7f}")
print(f"  (shipped/baseline corrected_44 ensemble: 11 errors = 2 FN + 9 FP)")
print("="*56)
print("artefacts →", OUT)
for f in sorted(os.listdir(OUT)): print("  ", f, f"{os.path.getsize(os.path.join(OUT,f))//1024} KB")
