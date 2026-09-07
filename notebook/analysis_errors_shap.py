import os, numpy as np, pandas as pd, joblib, collections, shap, warnings
warnings.filterwarnings("ignore")
from sklearn.model_selection import train_test_split
ROOT="notebook/artifacts/corrected_44"; OUT="notebook/artefacts_corrected"; THR=0.50
z=np.load(next(os.path.join(ROOT,f) for f in os.listdir(ROOT) if f.endswith(".npz")),allow_pickle=True)
X,y=z["features"],z["labels"]; names=list(z["feature_names"])
st=X[:,names.index("stNum")].astype(float); sq=X[:,names.index("sqNum")].astype(float); S=pd.Series(st)
d=np.diff(st,prepend=st[0]); ctx={}
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
pk=joblib.load(f"{OUT}/ids_lgbm_ensemble_corrected.joblib"); qlo,qhi=pk["q_lo_ms"],pk["q_hi_ms"]; final=pk["feature_names"]; models=pk["models"]
dte=pd.DataFrame(Xte,columns=alln); ms=dte["time_delta"].values*1000
dte["dt_in_baseline_flag"]=((ms>=qlo)&(ms<=qhi)).astype(int); dte["dt_below_baseline"]=(ms<qlo).astype(int); dte["dt_above_baseline"]=(ms>qhi).astype(int)
dte["dt_in_pub_baseline_flag"]=0; dte["dt_above_pub_baseline"]=0; dte["dt_below_pub_baseline"]=0
Mte=dte[final].values
score=np.mean([m.predict(Mte,num_iteration=m.best_iteration) for m in models],axis=0)
pred=(score>=THR).astype(int)
row2score=dict(zip(ite,score)); test_set=set(ite.tolist())

# collinear keys (both classes on same (stNum,sqNum))
lab=collections.defaultdict(set)
for a,b_,l in zip(st.astype(int),sq.astype(int),y): lab[(a,b_)].add(int(l))
both_keys={k for k,v in lab.items() if v=={0,1}}

# reconstruct attack blocks over full corpus
atk=np.flatnonzero(y==1); ast_,asq,arow=st[atk].astype(int),sq[atk].astype(int),atk
blk=np.empty(len(atk),int); b=-1; ps=pq=None; block_rows=collections.defaultdict(list); block_start={}
for i in range(len(atk)):
    if ps is None or ast_[i]!=ps or asq[i]!=pq+1:
        b+=1; block_start[b]=arow[i]
    blk[i]=b; block_rows[b].append(arow[i]); ps,pq=ast_[i],asq[i]
row2blk={r:bl for bl,rs in block_rows.items() for r in rs}
nblk=b+1

# ---- errors ----
el=np.flatnonzero(pred!=yte)
err_rows=ite[el]
# SHAP on error rows (avg over the 5 boosters)
idxpos={r:i for i,r in enumerate(ite)}
rowsX=Mte[[idxpos[r] for r in err_rows]]
shp=np.mean([shap.TreeExplainer(m).shap_values(rowsX) for m in models],axis=0)
if isinstance(shp,list): shp=shp[1] if len(shp)>1 else shp[0]
print("="*70); print("PROMPT 3 — ERROR ANALYSIS (retained corrected model, thr=0.50)"); print("="*70)
print(f"errors: {len(el)}  (FN={int(((yte[el]==1)).sum())}, FP={int((yte[el]==0).sum())})\n")
for j,r in enumerate(err_rows):
    kind="FN" if yte[el[j]]==1 else "FP"
    key=(int(st[r]),int(sq[r])); collin = key in both_keys
    top=np.argsort(-np.abs(shp[j]))[:3]
    feats=", ".join(f"{final[t]}{'+' if shp[j][t]>=0 else '−'}{abs(shp[j][t]):.2f}" for t in top)
    bl=row2blk.get(r,None)
    print(f"[{kind}] csv_row={r:7d} score={row2score[r]:.4f} stNum={key[0]} sqNum={key[1]} "
          f"{'COLLINEAR' if collin else 'separable'} block={bl}")
    print(f"      top SHAP: {feats}")

# clustering of errors: same block / adjacent csv_row / same key
print("\n-- clustering --")
er=sorted(err_rows.tolist())
clusters=[]
for r in er:
    placed=False
    for c in clusters:
        if any(abs(r-x)<=50 for x in c) or (row2blk.get(r)==row2blk.get(c[0]) and row2blk.get(r) is not None):
            c.append(r); placed=True; break
    if not placed: clusters.append([r])
multi=[c for c in clusters if len(c)>1]
print(f"error rows grouping into {len(clusters)} clusters; multi-row clusters: {multi if multi else 'none (all isolated)'}")

# ---- frame vs episode recall ----
tp=int(((pred==1)&(yte==1)).sum()); fn=int(((pred==0)&(yte==1)).sum())
frame_recall=tp/(tp+fn)
present=[bl for bl in range(nblk) if any(r in test_set for r in block_rows[bl])]
detected=[bl for bl in present if any((r in test_set and row2score[r]>=THR) for r in block_rows[bl])]
print("\n-- recall --")
print(f"FRAME-level recall (test)   : {frame_recall:.6f}  (TP={tp}, FN={fn})")
print(f"EPISODE-level recall (test) : {len(detected)/len(present):.6f}  "
      f"({len(detected)}/{len(present)} test-present blocks detected by >=1 frame)")
# each FN: block detected by other frames?
for j,r in enumerate(err_rows):
    if yte[el[j]]!=1: continue
    bl=row2blk[r]; frames=[x for x in block_rows[bl] if x in test_set]
    det=[x for x in frames if row2score[x]>=THR]
    print(f"  FN csv_row={r}: block {bl} has {len(frames)} test frames, {len(det)} detected "
          f"→ episode {'DETECTED by other frames' if det else 'MISSED entirely'}")

# ---- onset blind spot ----
onset_test=[bl for bl in range(nblk) if block_start[bl] in test_set]
onset_below=[bl for bl in onset_test if row2score[block_start[bl]]<THR]
print("\n-- onset blind spot --")
print(f"blocks whose ONSET frame is in test : {len(onset_test)}")
print(f"  of those, onset scores < threshold: {len(onset_below)} ({len(onset_below)/max(1,len(onset_test))*100:.1f}%)")
print(f"  → onset blind spot affects {len(onset_below)} test blocks"
      + (f" (e.g. blocks {onset_below[:8]})" if onset_below else " — onset blind spot does NOT survive"))
