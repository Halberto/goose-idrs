#!/usr/bin/env python
"""
analysis_mcnemar_ablation.py
============================
Two questions the benchmark memo raised:

  (1) Is "LightGBM best, XGBoost second" real, or are they statistically
      indistinguishable at 10 vs 15 errors? -> paired McNemar tests on the
      corrected 53-feature test split at each model's target-recall operating
      point.

  (2) Is Models.ipynb's XGBoost (518 FP) worse because of the *representation*
      or the *corpus*? -> a clean ablation: same model, same corrected split,
      same policy, 53-feature vs a minimalist 6-feature set. This isolates the
      representation (corpus and split held fixed).

Writes analysis_out_corrected/mcnemar_ablation.json and paired predictions.
Trees only -> fast, fully deterministic.
"""
import os, json, numpy as np, pandas as pd, joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from scipy.stats import binomtest, chi2
import lightgbm as lgb, xgboost as xgb

ROOT = "notebook/artifacts/corrected_44"; ART = "notebook/artefacts_corrected"; AO = "analysis_out_corrected"
SEED, TEST_SIZE, VAL_SIZE = 42, 0.30, 0.20
TARGET_RECALL, VAL_FLOOR = 0.9998, 0.99990

# ---- corpus: 53-feature representation + a minimalist 6-feature subset -------
z = np.load(next(os.path.join(ROOT, f) for f in os.listdir(ROOT) if f.endswith(".npz")), allow_pickle=True)
X, y = z["features"], z["labels"].astype(int); names = list(z["feature_names"])
st = X[:, names.index("stNum")].astype(float); sq = X[:, names.index("sqNum")].astype(float); S = pd.Series(st)
d = np.diff(st, prepend=st[0])
ctx = {"ctx_st_back_count_w20": pd.Series((d < 0).astype(float)).rolling(20, min_periods=1).sum().values,
       "ctx_st_threads_w20": S.rolling(20, min_periods=1).apply(lambda a: len(np.unique(a)), raw=True).values}
fwd = np.full(len(st), np.inf)
for k in (1, 2, 3):
    sh = np.full(len(st), np.inf); sh[:-k] = st[k:]; fwd = np.minimum(fwd, sh)
ctx["ctx_lower_stnum_next3"] = ((fwd < st) & np.isfinite(fwd)).astype(float)
cn = ["ctx_lower_stnum_next3", "ctx_st_back_count_w20", "ctx_st_threads_w20"]
Xc = np.column_stack([X] + [ctx[n] for n in cn]); alln = names + cn
pk = joblib.load(f"{ART}/ids_lgbm_ensemble_corrected.joblib"); qlo, qhi = pk["q_lo_ms"], pk["q_hi_ms"]; final = pk["feature_names"]
D = pd.DataFrame(Xc, columns=alln); ms = D["time_delta"].values * 1000
D["dt_in_baseline_flag"] = ((ms >= qlo) & (ms <= qhi)).astype(int)
D["dt_below_baseline"] = (ms < qlo).astype(int); D["dt_above_baseline"] = (ms > qhi).astype(int)
D["dt_in_pub_baseline_flag"] = 0; D["dt_above_pub_baseline"] = 0; D["dt_below_pub_baseline"] = 0
M53 = D[final].values.astype(np.float32)
SIMPLE = ["sqNum", "stNum", "time_delta", "sqNum_diff", "stNum_diff", "time_delta_zscore"]  # minimalist 6
M6 = D[SIMPLE].values.astype(np.float32)

idx = np.arange(len(y))
def split(Xin):
    Xa, Xte, ia, ite, ya, yte = train_test_split(Xin, idx, y, test_size=TEST_SIZE, random_state=SEED, stratify=y)
    Xtr, Xva, _, _, ytr, yva = train_test_split(Xa, ia, ya, test_size=VAL_SIZE, random_state=SEED, stratify=ya)
    return Xtr, Xva, Xte, ytr, yva, yte, ite
Xtr53, Xva53, Xte53, ytr, yva, yte, ite = split(M53)
Xtr6,  Xva6,  Xte6,  _,   _,   _,   _   = split(M6)

def select_threshold(yv, pv):
    grid = np.unique(np.concatenate([np.linspace(0, 1, 2001), pv]))
    best = None
    for t in grid:
        pred = pv >= t; tp = int((pred & (yv == 1)).sum()); fn = int((~pred & (yv == 1)).sum())
        rec = tp / (tp + fn) if (tp + fn) else 0
        if rec >= VAL_FLOOR:
            fp = int((pred & (yv == 0)).sum()); key = (fp, -t)
            if best is None or key < best[0]: best = (key, t)
    return best[1] if best else 0.5

def cm_at(yv, pv, yt, pt):
    thr = select_threshold(yv, pv); pred = (pt >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, pred).ravel()
    return pred, dict(threshold=float(thr), TN=int(tn), FP=int(fp), FN=int(fn), TP=int(tp), errors=int(fp + fn))

# ---- fit the three tree models on 53 features; collect test predictions ------
def lgb_pred():                                   # retained ensemble = the headline family
    pv = np.mean([m.predict(Xva53, num_iteration=m.best_iteration) for m in pk["models"]], axis=0)
    pt = np.mean([m.predict(Xte53, num_iteration=m.best_iteration) for m in pk["models"]], axis=0)
    return cm_at(yva, pv, yte, pt)
def xgb_pred(Xtr, Xva_, Xte_):
    spw = float((ytr == 0).sum() / (ytr == 1).sum())
    m = xgb.XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.9,
                          colsample_bytree=0.9, scale_pos_weight=spw, eval_metric="logloss",
                          n_jobs=-1, random_state=SEED, tree_method="hist")
    m.fit(Xtr, ytr)
    return cm_at(yva, m.predict_proba(Xva_)[:, 1], yte, m.predict_proba(Xte_)[:, 1])
def rf_pred():
    m = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight="balanced_subsample",
                               n_jobs=-1, random_state=SEED)
    m.fit(Xtr53, ytr)
    return cm_at(yva, m.predict_proba(Xva53)[:, 1], yte, m.predict_proba(Xte53)[:, 1])

pred_lgb, cm_lgb = lgb_pred()
pred_xgb, cm_xgb = xgb_pred(Xtr53, Xva53, Xte53)
pred_rf,  cm_rf  = rf_pred()
print("53-feature operating points (target-recall policy):")
for n, c in [("LightGBM", cm_lgb), ("XGBoost", cm_xgb), ("RandomForest", cm_rf)]:
    print(f"  {n:13s} FP={c['FP']:>3} FN={c['FN']:>3} errors={c['errors']:>3}")

# ---- McNemar on paired misclassifications ------------------------------------
def mcnemar(pa, pb, yt):
    wa = pa != yt; wb = pb != yt              # wrong masks
    b = int((wa & ~wb).sum())                 # A wrong, B right
    c = int((~wa & wb).sum())                 # A right, B wrong
    n = b + c
    p_exact = float(binomtest(min(b, c), n, 0.5).pvalue) if n > 0 else 1.0
    chi = ((abs(b - c) - 1) ** 2 / n) if n > 0 else 0.0
    p_chi = float(chi2.sf(chi, 1)) if n > 0 else 1.0
    return dict(b_AwrongBright=b, c_ArightBwrong=c, discordant=n,
                p_exact=p_exact, chi2_cc=float(chi), p_chi2=p_chi)

pairs = {"LightGBM_vs_XGBoost": mcnemar(pred_lgb, pred_xgb, yte),
         "LightGBM_vs_RandomForest": mcnemar(pred_lgb, pred_rf, yte),
         "XGBoost_vs_RandomForest": mcnemar(pred_xgb, pred_rf, yte)}
print("\nMcNemar (paired, corrected 53-feature test split):")
for k, v in pairs.items():
    sig = "SIGNIFICANT" if v["p_exact"] < 0.05 else "not significant"
    print(f"  {k:26s} b={v['b_AwrongBright']:>3} c={v['c_ArightBwrong']:>3} "
          f"p_exact={v['p_exact']:.4f}  -> {sig}")

# ---- representation ablation: 53-feature vs minimalist 6-feature -------------
_, cm_xgb6 = xgb_pred(Xtr6, Xva6, Xte6)
# a single LightGBM (not the ensemble) for a clean 6-vs-53 single-model contrast
def lgb_single(Xtr, Xva_, Xte_):
    spw = float((ytr == 0).sum() / (ytr == 1).sum())
    tr = lgb.Dataset(Xtr, ytr); va = lgb.Dataset(Xva_, yva, reference=tr)
    m = lgb.train(dict(objective="binary", metric="binary_logloss", num_leaves=63, learning_rate=0.05,
                       scale_pos_weight=spw, verbose=-1, seed=SEED, num_threads=-1),
                  tr, num_boost_round=400, valid_sets=[va], callbacks=[lgb.early_stopping(30, verbose=False)])
    return cm_at(yva, m.predict(Xva_, num_iteration=m.best_iteration), yte, m.predict(Xte_, num_iteration=m.best_iteration))
_, cm_lgb6 = lgb_single(Xtr6, Xva6, Xte6)
_, cm_lgb53s = lgb_single(Xtr53, Xva53, Xte53)
print("\nRepresentation ablation (same corrected split, same policy, same model):")
print(f"  XGBoost   6-feature: FP={cm_xgb6['FP']:>4} FN={cm_xgb6['FN']:>3} errors={cm_xgb6['errors']:>4}"
      f"   |  53-feature: FP={cm_xgb['FP']:>3} FN={cm_xgb['FN']:>3} errors={cm_xgb['errors']}")
print(f"  LightGBM  6-feature: FP={cm_lgb6['FP']:>4} FN={cm_lgb6['FN']:>3} errors={cm_lgb6['errors']:>4}"
      f"   |  53-feature: FP={cm_lgb53s['FP']:>3} FN={cm_lgb53s['FN']:>3} errors={cm_lgb53s['errors']}")

# ---- save provenance ---------------------------------------------------------
os.makedirs(AO, exist_ok=True)
pd.DataFrame({"csv_row": ite, "y_true": yte,
             "pred_lightgbm": pred_lgb, "pred_xgboost": pred_xgb, "pred_rf": pred_rf}).to_csv(
    f"{AO}/paired_predictions_trees.csv", index=False)
json.dump(dict(policy=dict(target_recall=TARGET_RECALL, val_floor=VAL_FLOOR, test_n=int(len(yte)),
                           feature_count=53, simple_features=SIMPLE),
               operating_points=dict(LightGBM=cm_lgb, XGBoost=cm_xgb, RandomForest=cm_rf),
               mcnemar=pairs,
               ablation=dict(xgboost_6feat=cm_xgb6, xgboost_53feat=cm_xgb,
                             lightgbm_6feat=cm_lgb6, lightgbm_53feat=cm_lgb53s),
               note_301642="Models.ipynb neural block uses SEQUENCE_LENGTH=20; test sequences = 301661-19 = 301642 (windowing edge, benign)."),
          open(f"{AO}/mcnemar_ablation.json", "w"), indent=2)
print(f"\nsaved: {AO}/mcnemar_ablation.json, {AO}/paired_predictions_trees.csv")
