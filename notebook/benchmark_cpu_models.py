import argparse
import gc
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path


os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

import joblib
import numpy as np
import psutil


REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = REPO_ROOT / "notebook" / "models" / "goose_detectors"
IDRS_MODEL = REPO_ROOT / "idrs" / "artifacts" / "ids_lgbm_model.joblib"

DEFAULT_WARMUP = 100
DEFAULT_REPS = 2000
SEQ_LEN = 10
INPUT_DIM = 26

DEFAULT_CPU_MODELS = ("rf", "xgb", "lgbm_idrs", "lgbm_opt", "gru", "transformer")
CPU_MODEL_CHOICES = DEFAULT_CPU_MODELS + ("mamba",)


def rss_mb():
    return psutil.Process(os.getpid()).memory_info().rss / 1024**2


def file_mb(path):
    return Path(path).stat().st_size / 1024**2


def pct(values, p):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * p) - 1))
    return ordered[index]


def summarize_ms(values):
    return {
        "mean_ms": statistics.fmean(values),
        "std_ms": statistics.pstdev(values),
        "p50_ms": statistics.median(values),
        "p95_ms": pct(values, 0.95),
        "max_ms": max(values),
        "repetitions": len(values),
    }


def package_version(name):
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return None


def environment_metadata():
    packages = {
        "numpy": package_version("numpy"),
        "joblib": package_version("joblib"),
        "psutil": package_version("psutil"),
        "scikit-learn": package_version("scikit-learn"),
        "lightgbm": package_version("lightgbm"),
        "xgboost": package_version("xgboost"),
        "torch": package_version("torch"),
        "mamba-ssm": package_version("mamba-ssm"),
    }
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_physical": psutil.cpu_count(logical=False),
        "cpu_logical": psutil.cpu_count(logical=True),
        "ram_total_mb": psutil.virtual_memory().total / 1024**2,
        "thread_env": {
            "OMP_NUM_THREADS": os.environ.get("OMP_NUM_THREADS"),
            "OPENBLAS_NUM_THREADS": os.environ.get("OPENBLAS_NUM_THREADS"),
            "MKL_NUM_THREADS": os.environ.get("MKL_NUM_THREADS"),
            "NUMEXPR_NUM_THREADS": os.environ.get("NUMEXPR_NUM_THREADS"),
        },
        "packages": packages,
    }


def benchmark_callable(predict_fn, sample, warmup, reps):
    for _ in range(warmup):
        predict_fn(sample)

    times = []
    for _ in range(reps):
        start = time.perf_counter_ns()
        predict_fn(sample)
        times.append((time.perf_counter_ns() - start) / 1_000_000)
    return times


def result_template(model_name, warmup, reps):
    return {
        "model": model_name,
        "backend": "cpu",
        "metric_scope": "single_frame_predict_only_after_warmup",
        "memory_scope": "process_rss_mb",
        "warmup": warmup,
        "repetitions": reps,
        "pid": os.getpid(),
        "cwd": str(REPO_ROOT),
        "environment": environment_metadata(),
        "rss_after_imports_mb": rss_mb(),
    }


def emit_result(result, output_dir):
    if "timing" in result:
        timing = result["timing"]
        print(f"wall_mean_ms={timing['mean_ms']:.6f}")
        print(f"wall_std_ms={timing['std_ms']:.6f}")
        print(f"wall_p50_ms={timing['p50_ms']:.6f}")
        print(f"wall_p95_ms={timing['p95_ms']:.6f}")
        print(f"wall_max_ms={timing['max_ms']:.6f}")
    for key in (
        "model",
        "backend",
        "n_features",
        "params",
        "serialized_mb",
        "rss_after_model_load_mb",
        "rss_after_warmup_mb",
        "rss_final_mb",
    ):
        if key in result:
            print(f"{key}={result[key]}")

    if output_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{result['model']}_cpu_benchmark.json"
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(f"json_output={out_path}")


def bench_rf(warmup, reps):
    result = result_template("rf", warmup, reps)
    model_path = MODEL_DIR / "rf_single_cell_model.joblib"
    model = joblib.load(model_path)
    model.n_jobs = 1
    model.verbose = 0
    sample = np.zeros((1, int(model.n_features_in_)), dtype=np.float32)
    result.update(
        {
            "artifact": str(model_path),
            "n_features": sample.shape[1],
            "serialized_mb": file_mb(model_path),
            "rss_after_model_load_mb": rss_mb(),
        }
    )
    times = benchmark_callable(model.predict, sample, warmup, reps)
    result["rss_after_warmup_mb"] = result["rss_after_model_load_mb"]
    result["timing"] = summarize_ms(times)
    result["rss_final_mb"] = rss_mb()
    return result


def bench_xgb(warmup, reps):
    result = result_template("xgb", warmup, reps)
    model_path = MODEL_DIR / "xgb_optimized_model.joblib"
    model = joblib.load(model_path)
    booster = model.get_booster()
    booster.set_param({"nthread": 1})
    n_features = int(getattr(model, "n_features_in_", booster.num_features()))
    sample = np.zeros((1, n_features), dtype=np.float32)
    result.update(
        {
            "artifact": str(model_path),
            "n_features": sample.shape[1],
            "serialized_mb": file_mb(model_path),
            "rss_after_model_load_mb": rss_mb(),
        }
    )
    times = benchmark_callable(model.predict, sample, warmup, reps)
    result["rss_after_warmup_mb"] = result["rss_after_model_load_mb"]
    result["timing"] = summarize_ms(times)
    result["rss_final_mb"] = rss_mb()
    return result


def bench_lgbm_idrs(warmup, reps):
    result = result_template("lgbm_idrs", warmup, reps)
    package = joblib.load(IDRS_MODEL)
    model = package["lgbm_model"]
    feature_names = list(package["feature_names"])
    best = getattr(model, "best_iteration", None)
    sample = np.zeros((1, len(feature_names)), dtype=np.float32)
    result.update(
        {
            "artifact": str(IDRS_MODEL),
            "n_features": sample.shape[1],
            "serialized_mb": file_mb(IDRS_MODEL),
            "rss_after_model_load_mb": rss_mb(),
        }
    )
    times = benchmark_callable(lambda x: model.predict(x, num_iteration=best), sample, warmup, reps)
    result["rss_after_warmup_mb"] = result["rss_after_model_load_mb"]
    result["timing"] = summarize_ms(times)
    result["rss_final_mb"] = rss_mb()
    return result


def bench_lgbm_opt(warmup, reps):
    result = result_template("lgbm_opt", warmup, reps)
    model_path = MODEL_DIR / "lgbm_optimized_model.joblib"
    model = joblib.load(model_path)
    best = getattr(model, "best_iteration", None)
    sample = np.zeros((1, model.num_feature()), dtype=np.float32)
    result.update(
        {
            "artifact": str(model_path),
            "n_features": sample.shape[1],
            "serialized_mb": file_mb(model_path),
            "rss_after_model_load_mb": rss_mb(),
        }
    )
    times = benchmark_callable(lambda x: model.predict(x, num_iteration=best), sample, warmup, reps)
    result["rss_after_warmup_mb"] = result["rss_after_model_load_mb"]
    result["timing"] = summarize_ms(times)
    result["rss_final_mb"] = rss_mb()
    return result


def load_torch_cpu():
    import torch
    from torch import nn

    torch.set_num_threads(1)
    return torch, nn


def bench_torch_model(model_name, model, state_path, warmup, reps):
    torch, _ = load_torch_cpu()
    result = result_template(model_name, warmup, reps)
    start = time.perf_counter()
    model.load_state_dict(torch.load(state_path, map_location="cpu"))
    result["load_s"] = time.perf_counter() - start
    model.eval()
    sample = torch.zeros((1, SEQ_LEN, INPUT_DIM), dtype=torch.float32)
    result.update(
        {
            "artifact": str(state_path),
            "params": sum(p.numel() for p in model.parameters()),
            "state_dict_file_mb": file_mb(state_path),
            "rss_after_model_load_mb": rss_mb(),
        }
    )

    with torch.no_grad():
        for _ in range(warmup):
            model(sample)
    result["rss_after_warmup_mb"] = rss_mb()

    times = []
    with torch.no_grad():
        for _ in range(reps):
            start = time.perf_counter_ns()
            model(sample)
            times.append((time.perf_counter_ns() - start) / 1_000_000)
    result["timing"] = summarize_ms(times)
    result["rss_final_mb"] = rss_mb()
    return result


def bench_gru(warmup, reps):
    _, nn = load_torch_cpu()

    class GRUModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.hidden_dim = 64
            self.layer_dim = 2
            self.gru = nn.GRU(INPUT_DIM, 64, 2, batch_first=True, dropout=0.2, bidirectional=True)
            self.attention = nn.Sequential(nn.Linear(128, 64), nn.Tanh(), nn.Linear(64, 1), nn.Softmax(dim=1))
            self.fc = nn.Sequential(nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.2), nn.Linear(64, 2))

        def forward(self, x):
            import torch

            h0 = torch.zeros(self.layer_dim * 2, x.size(0), self.hidden_dim, device=x.device, dtype=x.dtype)
            out, _ = self.gru(x, h0)
            weights = self.attention(out)
            context = torch.sum(weights * out, dim=1)
            return self.fc(context)

    return bench_torch_model("gru", GRUModel(), MODEL_DIR / "gru_model.pth", warmup, reps)


def bench_transformer(warmup, reps):
    import torch

    _, nn = load_torch_cpu()

    class TransformerModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.input_embedding = nn.Linear(INPUT_DIM, 128)
            self.pos_encoder = nn.Sequential(nn.Linear(128, 128), nn.LayerNorm(128), nn.ReLU())
            layer = nn.TransformerEncoderLayer(
                d_model=128,
                nhead=4,
                dim_feedforward=256,
                dropout=0.1,
                batch_first=True,
                norm_first=True,
            )
            self.transformer_encoder = nn.TransformerEncoder(layer, num_layers=2)
            self.output_layer = nn.Sequential(nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.1), nn.Linear(64, 2))

        def forward(self, x):
            seq_len = x.size(1)
            mask = torch.triu(torch.ones(seq_len, seq_len, device=x.device), diagonal=1)
            mask = mask.float().masked_fill(mask == 1, float("-inf")).masked_fill(mask == 0, 0.0)
            x = self.input_embedding(x)
            x = self.pos_encoder(x)
            x = self.transformer_encoder(x, mask)
            return self.output_layer(x[:, -1, :])

    return bench_torch_model("transformer", TransformerModel(), MODEL_DIR / "transformer_model.pth", warmup, reps)


def bench_mamba(warmup, reps):
    _, nn = load_torch_cpu()
    import mamba_ssm

    class MambaModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.input_proj = nn.Linear(INPUT_DIM, 64)
            self.norm1 = nn.LayerNorm(64)
            self.mamba = mamba_ssm.Mamba(d_model=64, d_state=8, d_conv=2, expand=1.5)
            self.norm2 = nn.LayerNorm(64)
            self.dropout = nn.Dropout(0.1)
            self.output_proj = nn.Linear(64, 2)

        def forward(self, x):
            x = self.norm1(self.input_proj(x))
            x = self.mamba(x)
            x = self.norm2(x[:, -1, :])
            x = self.dropout(x)
            return self.output_proj(x)

    return bench_torch_model("mamba", MambaModel(), MODEL_DIR / "mamba_model.pth", warmup, reps)


BENCHMARKS = {
    "rf": bench_rf,
    "xgb": bench_xgb,
    "lgbm_idrs": bench_lgbm_idrs,
    "lgbm_opt": bench_lgbm_opt,
    "gru": bench_gru,
    "mamba": bench_mamba,
    "transformer": bench_transformer,
}


def run_all(args):
    failures = []
    for model_name in DEFAULT_CPU_MODELS:
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            model_name,
            "--warmup",
            str(args.warmup),
            "--reps",
            str(args.reps),
        ]
        if args.output_dir:
            command.extend(["--output-dir", args.output_dir])
        print(f"running={' '.join(command)}")
        completed = subprocess.run(command, cwd=REPO_ROOT)
        if completed.returncode:
            failures.append(model_name)
    if failures:
        raise SystemExit(f"benchmarks failed: {', '.join(failures)}")


def main():
    parser = argparse.ArgumentParser(description="CPU runtime benchmark for saved GOOSEIDRS model artifacts.")
    parser.add_argument("model", choices=CPU_MODEL_CHOICES + ("all",))
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--reps", type=int, default=DEFAULT_REPS)
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    if args.model == "all":
        run_all(args)
        return

    try:
        result = BENCHMARKS[args.model](args.warmup, args.reps)
        emit_result(result, args.output_dir)
    finally:
        gc.collect()


if __name__ == "__main__":
    main()
