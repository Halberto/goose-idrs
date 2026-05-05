import argparse
import gc
import math
import os
import statistics
import time
import warnings

import joblib
import numpy as np
import psutil


warnings.filterwarnings("ignore")

N_WARMUP = 100
N_REPS = 2000
SEQ_LEN = 10
INPUT_DIM = 26


def rss_mb():
    return psutil.Process(os.getpid()).memory_info().rss / 1024**2


def pct(values, p):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * p) - 1))
    return ordered[index]


def print_stats(label, values):
    print(f"{label}_mean_ms={statistics.fmean(values):.6f}")
    print(f"{label}_std_ms={statistics.pstdev(values):.6f}")
    print(f"{label}_p50_ms={statistics.median(values):.6f}")
    print(f"{label}_p95_ms={pct(values, 0.95):.6f}")
    print(f"{label}_max_ms={max(values):.6f}")


def bench_cpu_predict(model_name, predict_fn, sample):
    for _ in range(N_WARMUP):
        predict_fn(sample)
    times = []
    for _ in range(N_REPS):
        t0 = time.perf_counter_ns()
        predict_fn(sample)
        times.append((time.perf_counter_ns() - t0) / 1_000_000)
    print_stats("wall", times)


def bench_rf():
    model = joblib.load("notebook/models/goose_detectors/rf_single_cell_model.joblib")
    model.n_jobs = 1
    model.verbose = 0
    sample = np.zeros((1, int(model.n_features_in_)), dtype=np.float32)
    print(f"n_features={sample.shape[1]}")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/rf_single_cell_model.joblib') / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    bench_cpu_predict("rf", model.predict, sample)
    print(f"rss_final_mb={rss_mb():.3f}")


def bench_xgb_cpu():
    model = joblib.load("notebook/models/goose_detectors/xgb_optimized_model.joblib")
    sample = np.zeros((1, int(model.n_features_in_)), dtype=np.float32)
    print(f"n_features={sample.shape[1]}")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/xgb_optimized_model.joblib') / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    bench_cpu_predict("xgb_cpu", model.predict, sample)
    print(f"rss_final_mb={rss_mb():.3f}")


def bench_xgb_gpu():
    import cupy as cp

    model = joblib.load("notebook/models/goose_detectors/xgb_optimized_model.joblib")
    # This saved model already carries legacy GPU metadata
    # (gpu_id=0, tree_method=gpu_hist). Forcing device="cuda" on newer
    # XGBoost builds conflicts with the persisted gpu_id setting.
    sample = cp.zeros((1, int(model.get_booster().num_features())), dtype=cp.float32)
    print(f"n_features={sample.shape[1]}")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/xgb_optimized_model.joblib') / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    for _ in range(N_WARMUP):
        model.predict(sample)
    cp.cuda.Stream.null.synchronize()

    times = []
    start = cp.cuda.Event()
    end = cp.cuda.Event()
    for _ in range(N_REPS):
        start.record()
        model.predict(sample)
        end.record()
        end.synchronize()
        times.append(cp.cuda.get_elapsed_time(start, end))
    print_stats("cuda_event", times)
    print(f"cupy_pool_used_mb={cp.get_default_memory_pool().used_bytes() / 1024**2:.3f}")
    print(f"cupy_pool_total_mb={cp.get_default_memory_pool().total_bytes() / 1024**2:.3f}")
    print(f"rss_final_mb={rss_mb():.3f}")


def bench_lgbm_opt():
    model = joblib.load("notebook/models/goose_detectors/lgbm_optimized_model.joblib")
    n_features = model.num_feature()
    sample = np.zeros((1, n_features), dtype=np.float32)
    best = getattr(model, "best_iteration", None)
    print(f"n_features={n_features}")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/lgbm_optimized_model.joblib') / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    bench_cpu_predict("lgbm_opt", lambda x: model.predict(x, num_iteration=best), sample)
    print(f"rss_final_mb={rss_mb():.3f}")


def bench_lgbm_idrs():
    pkg = joblib.load("idrs/artifacts/ids_lgbm_model.joblib")
    model = pkg["lgbm_model"]
    names = list(pkg["feature_names"])
    sample = np.zeros((1, len(names)), dtype=np.float32)
    best = getattr(model, "best_iteration", None)
    print(f"n_features={sample.shape[1]}")
    print(f"serialized_mb={os.path.getsize('idrs/artifacts/ids_lgbm_model.joblib') / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    bench_cpu_predict("lgbm_idrs", lambda x: model.predict(x, num_iteration=best), sample)
    print(f"rss_final_mb={rss_mb():.3f}")


def load_torch():
    import torch
    from torch import nn

    torch.set_num_threads(1)
    return torch, nn


def bench_gru():
    torch, nn = load_torch()

    class GRUModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.hidden_dim = 64
            self.layer_dim = 2
            self.gru = nn.GRU(INPUT_DIM, 64, 2, batch_first=True, dropout=0.2, bidirectional=True)
            self.attention = nn.Sequential(nn.Linear(128, 64), nn.Tanh(), nn.Linear(64, 1), nn.Softmax(dim=1))
            self.fc = nn.Sequential(nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.2), nn.Linear(64, 2))

        def forward(self, x):
            h0 = torch.zeros(self.layer_dim * 2, x.size(0), self.hidden_dim, device=x.device, dtype=x.dtype)
            out, _ = self.gru(x, h0)
            weights = self.attention(out)
            context = torch.sum(weights * out, dim=1)
            return self.fc(context)

    bench_torch_model("gru", GRUModel(), "notebook/models/goose_detectors/gru_model.pth")


def bench_transformer():
    torch, nn = load_torch()

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

    bench_torch_model("transformer", TransformerModel(), "notebook/models/goose_detectors/transformer_model.pth")


def bench_mamba():
    torch, nn = load_torch()
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

    bench_torch_model("mamba", MambaModel(), "notebook/models/goose_detectors/mamba_model.pth")


def bench_torch_model(name, model, state_path):
    import torch

    print(f"torch_version={torch.__version__}")
    print(f"torch_cuda={torch.version.cuda}")
    print(f"cuda_available={torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available")
    device = torch.device("cuda")
    print(f"cuda_device={torch.cuda.get_device_name(0)}")
    print(f"rss_after_torch_import_mb={rss_mb():.3f}")

    model = model.to(device)
    t0 = time.perf_counter()
    model.load_state_dict(torch.load(state_path, map_location=device))
    print(f"load_s={time.perf_counter() - t0:.6f}")
    model.eval()
    print(f"params={sum(p.numel() for p in model.parameters())}")
    print(f"state_dict_file_mb={os.path.getsize(state_path) / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    print(f"cuda_alloc_after_model_load_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_after_model_load_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")

    sample = torch.zeros((1, SEQ_LEN, INPUT_DIM), dtype=torch.float32, device=device)
    torch.cuda.reset_peak_memory_stats()
    with torch.no_grad():
        for _ in range(N_WARMUP):
            model(sample)
        torch.cuda.synchronize()

    print(f"rss_after_warmup_mb={rss_mb():.3f}")
    print(f"cuda_alloc_after_warmup_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_peak_after_warmup_mb={torch.cuda.max_memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_after_warmup_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")

    cuda_times = []
    wall_times = []
    start = torch.cuda.Event(enable_timing=True)
    end = torch.cuda.Event(enable_timing=True)
    with torch.no_grad():
        for _ in range(N_REPS):
            t0 = time.perf_counter_ns()
            start.record()
            model(sample)
            end.record()
            torch.cuda.synchronize()
            wall_times.append((time.perf_counter_ns() - t0) / 1_000_000)
            cuda_times.append(start.elapsed_time(end))

    print_stats("cuda_event", cuda_times)
    print_stats("wall_sync", wall_times)
    print(f"rss_final_mb={rss_mb():.3f}")
    print(f"cuda_alloc_final_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_peak_final_mb={torch.cuda.max_memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_final_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "model",
        choices=[
            "rf",
            "xgb_cpu",
            "xgb_gpu",
            "lgbm_opt",
            "lgbm_idrs",
            "gru",
            "mamba",
            "transformer",
        ],
    )
    args = parser.parse_args()
    print(f"model={args.model}")
    print(f"pid={os.getpid()}")
    print(f"rss_after_imports_mb={rss_mb():.3f}")
    try:
        {
            "rf": bench_rf,
            "xgb_cpu": bench_xgb_cpu,
            "xgb_gpu": bench_xgb_gpu,
            "lgbm_opt": bench_lgbm_opt,
            "lgbm_idrs": bench_lgbm_idrs,
            "gru": bench_gru,
            "mamba": bench_mamba,
            "transformer": bench_transformer,
        }[args.model]()
    finally:
        gc.collect()


if __name__ == "__main__":
    main()
