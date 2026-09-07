import os, numpy as np, pandas as pd, joblib
from sklearn.model_selection import train_test_split
ROOT="notebook/artifacts/corrected_44"; OUT="notebook/artefacts_corrected"
z=np.load(next(os.path.join(ROOT,f) for f in os.listdir(ROOT) if f.endswith(".npz")),allow_pickle=True)
X,y=z["features"],z["labels"]; names=list(z["feature_names"])
st=X[:,names.index("stNum")].astype(float); sq=X[:,names.index("sqNum")].astype(float); S=pd.Series(st)

# rebuild the 3 ctx feats + guards exactly as the committed pipeline
d=np.diff(st,prepend=st[0]); ctx={}
ctx["ctx_lower_stnum_next3"]=None
ctx["ctx_st_back_count_w20"]=pd.Series((d<0).astype(float)).rolling(20,min_periods=1).sum().values
ctx["ctx_st_threads_w20"]=S.rolling(20,min_periods=1).apply(lambda a:len(np.unique(a)),raw=True).values
fwd=np.full(len(st),np.inf)
for k in (1,2,3):
    sh=np.full(len(st),np.inf); sh[:-k]=st[k:]; fwd=np.minimum(fwd,sh)
ctx["ctx_lower_stnum_next3"]=((fwd<st)&np.isfinite(fwd)).astype(float)
ctx_names=["ctx_lower_stnum_next3","ctx_st_back_count_w20","ctx_st_threads_w20"]
Xc=np.column_stack([X]+[ctx[n] for n in ctx_names]); alln=names+ctx_names
csv_row=np.arange(len(y))
Xa,Xte,ia,ite,ya,yte=train_test_split(Xc,csv_row,y,test_size=.30,random_state=42,stratify=y)
pk=joblib.load(f"{OUT}/ids_lgbm_ensemble_corrected.joblib"); qlo,qhi=pk["q_lo_ms"],pk["q_hi_ms"]; final=pk["feature_names"]
dte=pd.DataFrame(Xte,columns=alln); ms=dte["time_delta"].values*1000
dte["dt_in_baseline_flag"]=((ms>=qlo)&(ms<=qhi)).astype(int); dte["dt_below_baseline"]=(ms<qlo).astype(int); dte["dt_above_baseline"]=(ms>qhi).astype(int)
dte["dt_in_pub_baseline_flag"]=0; dte["dt_above_pub_baseline"]=0; dte["dt_below_pub_baseline"]=0
score=np.mean([m.predict(dte[final].values,num_iteration=m.best_iteration) for m in pk["models"]],axis=0)

# ---- VERIFY refit booster reproduces exported test scores EXACTLY ----
exp=pd.read_csv(f"{OUT}/test_predictions.csv")
# align by csv_row
order=pd.Series(np.arange(len(ite)),index=ite)
exp_sorted=exp.set_index("csv_row").loc[ite]
maxdiff=np.max(np.abs(score-exp_sorted["y_score"].values))
print(f"[verify] in-memory booster vs exported test scores: max|Δ| = {maxdiff:.2e}  "
      f"({'EXACT' if maxdiff==0 else 'exact to '+format(maxdiff,'.1e')})")
print(f"[verify] label alignment identical: {bool((yte==exp_sorted['y_true'].values).all())}")

# ================= BLOCK BOOTSTRAP — reconstructed blocks =================
# sort corpus by csv_row (already ordered), take attack rows, rebuild blocks:
# a new attack block starts when stNum changes or sqNum does not continue (+1).
atk = np.flatnonzero(y==1)
ast_, asq, arow = st[atk].astype(int), sq[atk].astype(int), atk
block_id=np.empty(len(atk),dtype=int); b=-1
prev_st=None; prev_sq=None
starts=[]
for i in range(len(atk)):
    new = (prev_st is None) or (ast_[i]!=prev_st) or (asq[i]!=prev_sq+1)
    if new: b+=1; starts.append(arow[i])
    block_id[i]=b; prev_st, prev_sq = ast_[i], asq[i]
n_blocks=b+1
test_rows=set(ite.tolist())
# per block: rows, whether start-in-test, whether any-frame-in-test
start_in_test=sum(1 for s in starts if s in test_rows)
blocks_any_in_test=len(set(block_id[np.isin(arow,list(test_rows))]))
# fragmentation: blocks split across train/test
import collections
rows_by_block=collections.defaultdict(list)
for i in range(len(atk)): rows_by_block[block_id[i]].append(arow[i])
split_blocks=sum(1 for bl,rs in rows_by_block.items()
                 if any(r in test_rows for r in rs) and any(r not in test_rows for r in rs))
print("\n================ BLOCK-BOOTSTRAP FRAGMENT CAVEAT ================")
print(f"attack rows (corpus)            : {len(atk):,}")
print(f"reconstructed attack blocks     : {n_blocks:,}")
print(f"attack-block STARTS in test     : {start_in_test:,} / {n_blocks:,} ({start_in_test/n_blocks*100:.1f}%)")
print(f"blocks with >=1 frame in test   : {blocks_any_in_test:,} / {n_blocks:,} ({blocks_any_in_test/n_blocks*100:.1f}%)")
print(f"blocks fragmented across splits : {split_blocks:,} / {n_blocks:,} ({split_blocks/n_blocks*100:.1f}%)")
print("→ random row split fragments almost every block across train/test, so a")
print("  block-level bootstrap CI on the test split is not clean; report frame-level")
print("  with this caveat, or resplit by whole blocks to get an unfragmented CI.")
