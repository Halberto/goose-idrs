import argparse
import gc
import math
import os
import statistics
import tempfile
import time
import warnings

import cupy as cp
import joblib
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


def bench_cupy_callable(predict_fn, sample):
    for _ in range(N_WARMUP):
        predict_fn(sample)
    cp.cuda.Stream.null.synchronize()

    times = []
    start = cp.cuda.Event()
    end = cp.cuda.Event()
    for _ in range(N_REPS):
        start.record()
        predict_fn(sample)
        end.record()
        end.synchronize()
        times.append(cp.cuda.get_elapsed_time(start, end))
    print_stats("cuda_event", times)


def print_cupy_memory():
    print(f"cupy_pool_used_mb={cp.get_default_memory_pool().used_bytes() / 1024**2:.3f}")
    print(f"cupy_pool_total_mb={cp.get_default_memory_pool().total_bytes() / 1024**2:.3f}")


def bench_rf_fil():
    from cuml import ForestInference

    model = joblib.load("notebook/models/goose_detectors/rf_single_cell_model.joblib")
    n_features = int(model.n_features_in_)
    print(f"source_model=sklearn_random_forest")
    print(f"n_features={n_features}")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/rf_single_cell_model.joblib') / 1024**2:.3f}")
    t0 = time.perf_counter()
    fil = ForestInference.load_from_sklearn(model, output_class=True, threshold=0.5)
    print(f"fil_load_s={time.perf_counter() - t0:.6f}")
    print(f"rss_after_fil_load_mb={rss_mb():.3f}")
    sample = cp.zeros((1, n_features), dtype=cp.float32)
    bench_cupy_callable(fil.predict, sample)
    print_cupy_memory()
    print(f"rss_final_mb={rss_mb():.3f}")


def bench_xgb_fil():
    from cuml import ForestInference

    model = joblib.load("notebook/models/goose_detectors/xgb_optimized_model.joblib")
    booster = model.get_booster()
    n_features = booster.num_features()
    print(f"source_model=xgboost_booster")
    print(f"n_features={n_features}")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/xgb_optimized_model.joblib') / 1024**2:.3f}")
    with tempfile.NamedTemporaryFile(suffix=".ubj", delete=False) as tmp:
        path = tmp.name
    try:
        booster.save_model(path)
        t0 = time.perf_counter()
        fil = ForestInference.load(path, output_class=True, threshold=0.5, model_type="xgboost_ubj")
        print(f"fil_load_s={time.perf_counter() - t0:.6f}")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    print(f"rss_after_fil_load_mb={rss_mb():.3f}")
    sample = cp.zeros((1, n_features), dtype=cp.float32)
    bench_cupy_callable(fil.predict, sample)
    print_cupy_memory()
    print(f"rss_final_mb={rss_mb():.3f}")


def load_lgbm_fil(model_path, package=False):
    from cuml import ForestInference

    obj = joblib.load(model_path)
    if package:
        model = obj["lgbm_model"]
        n_features = len(obj["feature_names"])
    else:
        model = obj
        n_features = model.num_feature()

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        path = tmp.name
    try:
        model.save_model(path)
        t0 = time.perf_counter()
        fil = ForestInference.load(path, output_class=False, threshold=0.5, model_type="lightgbm")
        print(f"fil_load_s={time.perf_counter() - t0:.6f}")
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return fil, n_features


def bench_lgbm_opt_fil():
    print(f"source_model=lightgbm_booster")
    print(f"serialized_mb={os.path.getsize('notebook/models/goose_detectors/lgbm_optimized_model.joblib') / 1024**2:.3f}")
    fil, n_features = load_lgbm_fil("notebook/models/goose_detectors/lgbm_optimized_model.joblib", package=False)
    print(f"n_features={n_features}")
    print(f"rss_after_fil_load_mb={rss_mb():.3f}")
    sample = cp.zeros((1, n_features), dtype=cp.float32)
    bench_cupy_callable(fil.predict, sample)
    print_cupy_memory()
    print(f"rss_final_mb={rss_mb():.3f}")


def bench_lgbm_idrs_fil():
    print(f"source_model=lightgbm_idrs_package")
    print(f"serialized_mb={os.path.getsize('idrs/artifacts/ids_lgbm_model.joblib') / 1024**2:.3f}")
    fil, n_features = load_lgbm_fil("idrs/artifacts/ids_lgbm_model.joblib", package=True)
    print(f"n_features={n_features}")
    print(f"rss_after_fil_load_mb={rss_mb():.3f}")
    sample = cp.zeros((1, n_features), dtype=cp.float32)
    bench_cupy_callable(fil.predict, sample)
    print_cupy_memory()
    print(f"rss_final_mb={rss_mb():.3f}")


def load_torch():
    import torch
    from torch import nn

    torch.set_num_threads(1)
    return torch, nn


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
    start = torch.cuda.Event(enable_timing=True)
    end = torch.cuda.Event(enable_timing=True)
    with torch.no_grad():
        for _ in range(N_REPS):
            start.record()
            model(sample)
            end.record()
            torch.cuda.synchronize()
            cuda_times.append(start.elapsed_time(end))
    print_stats("cuda_event", cuda_times)
    print(f"rss_final_mb={rss_mb():.3f}")
    print(f"cuda_alloc_final_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_peak_final_mb={torch.cuda.max_memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_final_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "model",
        choices=[
            "rf_fil",
            "xgb_fil",
            "lgbm_opt_fil",
            "lgbm_idrs_fil",
            "gru",
            "mamba",
            "transformer",
        ],
    )
    args = parser.parse_args()
    print(f"model={args.model}")
    print(f"pid={os.getpid()}")
    print(f"rss_after_imports_mb={rss_mb():.3f}")
    print(f"cuda_device={cp.cuda.runtime.getDeviceProperties(0)['name'].decode()}")
    try:
        {
            "rf_fil": bench_rf_fil,
            "xgb_fil": bench_xgb_fil,
            "lgbm_opt_fil": bench_lgbm_opt_fil,
            "lgbm_idrs_fil": bench_lgbm_idrs_fil,
            "gru": bench_gru,
            "mamba": bench_mamba,
            "transformer": bench_transformer,
        }[args.model]()
    finally:
        gc.collect()


if __name__ == "__main__":
    main()
