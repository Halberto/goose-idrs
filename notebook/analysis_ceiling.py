import os, numpy as np, pandas as pd, collections
ROOT="notebook/artifacts/corrected_44"
z=np.load(next(os.path.join(ROOT,f) for f in os.listdir(ROOT) if f.endswith(".npz")),allow_pickle=True)
X,y=z["features"],z["labels"]; names=list(z["feature_names"])
st=X[:,names.index("stNum")].astype(int); sq=X[:,names.index("sqNum")].astype(int)
key=np.array(list(zip(st,sq)),dtype=object)

lab=collections.defaultdict(set)
for a,b,l in zip(st,sq,y): lab[(a,b)].add(int(l))
both_keys={k for k,v in lab.items() if v=={0,1}}
onkey=np.array([(a,b) in both_keys for a,b in zip(st,sq)])

N=len(y); natk=int((y==1).sum()); nleg=int((y==0).sum())
rows_shared=int(onkey.sum())
atk_shared=int((onkey&(y==1)).sum()); leg_shared=int((onkey&(y==0)).sum())

print("="*70); print("PROMPT 4 — THE MISSING-SOURCE CEILING (measurement, no regeneration)"); print("="*70)
print(f"corpus rows                                   : {N:,}")
print(f"  legitimate                                  : {nleg:,}")
print(f"  attack                                      : {natk:,}")
print(f"\n(stNum,sqNum) keys total                      : {len(lab):,}")
print(f"(stNum,sqNum) keys carrying BOTH classes       : {len(both_keys):,}")
print(f"\nrows on a shared (both-class) key             : {rows_shared:,}  ({rows_shared/N*100:.2f}% of corpus)")
print(f"  attack rows on a shared key                 : {atk_shared:,}  ({atk_shared/natk*100:.2f}% of ALL attack rows)")
print(f"  legit rows on a shared key                  : {leg_shared:,}  ({leg_shared/nleg*100:.2f}% of ALL legit rows)")

# residual errors on shared keys (from retained run)
err=pd.read_csv("notebook/artefacts_corrected/test_predictions.csv")
err["pred"]=(err["y_score"]>=0.5).astype(int); err=err[err.pred!=err.y_true]
er=err["csv_row"].values
er_on=[( (int(st[r]),int(sq[r])) in both_keys ) for r in er]
print(f"\nresidual errors (retained model @0.50)        : {len(er)}")
print(f"  errors on a shared (collinear) key          : {sum(er_on)}/{len(er)}  ({sum(er_on)/len(er)*100:.0f}%)")

# ---- column inventory: base capture vs augmented corpus ----
base_cols=list(pd.read_csv("augmentation_framework/dataset/autosave_capture.csv",nrows=0).columns)
aug_cols =list(pd.read_csv("notebook/dataset/augmented_data.csv",nrows=0).columns)
dropped=[c for c in base_cols if c not in aug_cols]
print("\n"+"-"*70)
print("COLUMN INVENTORY — what augmentation discarded")
print("-"*70)
print(f"BASE capture ({len(base_cols)} cols): {base_cols}")
print(f"AUGMENTED    ({len(aug_cols)} cols): {aug_cols}")
print(f"DROPPED ({len(dropped)}): {dropped}")
ident={"src (source MAC)":"src","AppID":"appid","gocbRef":"gocbRef","confRev":"confRev"}
print("\nidentity/config fields the thesis asks about:")
for label,col in ident.items():
    inbase = col in base_cols; inaug = col in aug_cols
    print(f"  {label:20s} in base capture: {inbase!s:5}  | in augmented: {inaug!s:5}  | {'DROPPED' if inbase and not inaug else ('absent' if not inbase else 'kept')}")
