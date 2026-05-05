import os
import math
import statistics
import time

import psutil
import torch
from torch import nn
import mamba_ssm


MODEL_PATH = "notebook/models/goose_detectors/mamba_model.pth"
INPUT_DIM = 26
SEQ_LEN = 10
HIDDEN_DIM = 64
OUTPUT_DIM = 2
N_WARMUP = 100
N_REPS = 2000


class MambaModel(nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim, dropout_prob=0.2):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.norm1 = nn.LayerNorm(hidden_dim)
        self.mamba = mamba_ssm.Mamba(
            d_model=hidden_dim,
            d_state=8,
            d_conv=2,
            expand=1.5,
        )
        self.norm2 = nn.LayerNorm(hidden_dim)
        self.dropout = nn.Dropout(dropout_prob)
        self.output_proj = nn.Linear(hidden_dim, output_dim)

    def forward(self, x):
        x = self.norm1(self.input_proj(x))
        x = self.mamba(x)
        x = self.norm2(x[:, -1, :])
        x = self.dropout(x)
        return self.output_proj(x)


def rss_mb():
    return psutil.Process(os.getpid()).memory_info().rss / 1024**2


def pct(values, p):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * p) - 1))
    return ordered[index]


def main():
    print(f"torch_version={torch.__version__}")
    print(f"torch_cuda={torch.version.cuda}")
    print(f"mamba_ssm={getattr(mamba_ssm, '__version__', 'unknown')}")
    print(f"cuda_available={torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        raise SystemExit("CUDA is not available")

    torch.set_num_threads(1)
    device = torch.device("cuda")
    print(f"cuda_device={torch.cuda.get_device_name(0)}")
    print(f"rss_after_imports_mb={rss_mb():.3f}")

    model = MambaModel(INPUT_DIM, HIDDEN_DIM, OUTPUT_DIM, dropout_prob=0.1).to(device)
    t0 = time.perf_counter()
    state = torch.load(MODEL_PATH, map_location=device)
    model.load_state_dict(state)
    load_s = time.perf_counter() - t0
    model.eval()

    params = sum(p.numel() for p in model.parameters())
    print(f"load_s={load_s:.6f}")
    print(f"params={params}")
    print(f"state_dict_file_mb={os.path.getsize(MODEL_PATH) / 1024**2:.3f}")
    print(f"rss_after_model_load_mb={rss_mb():.3f}")
    print(f"cuda_alloc_after_model_load_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_after_model_load_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")

    x = torch.zeros((1, SEQ_LEN, INPUT_DIM), dtype=torch.float32, device=device)
    torch.cuda.reset_peak_memory_stats()

    with torch.no_grad():
        for _ in range(N_WARMUP):
            model(x)
        torch.cuda.synchronize()

    print(f"rss_after_warmup_mb={rss_mb():.3f}")
    print(f"cuda_alloc_after_warmup_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_peak_after_warmup_mb={torch.cuda.max_memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_after_warmup_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")

    cuda_times_ms = []
    wall_times_ms = []
    starter = torch.cuda.Event(enable_timing=True)
    ender = torch.cuda.Event(enable_timing=True)

    with torch.no_grad():
        for _ in range(N_REPS):
            t0 = time.perf_counter_ns()
            starter.record()
            model(x)
            ender.record()
            torch.cuda.synchronize()
            wall_times_ms.append((time.perf_counter_ns() - t0) / 1_000_000)
            cuda_times_ms.append(starter.elapsed_time(ender))

    for label, values in (("cuda_event", cuda_times_ms), ("wall_sync", wall_times_ms)):
        print(f"{label}_mean_ms={statistics.fmean(values):.6f}")
        print(f"{label}_std_ms={statistics.pstdev(values):.6f}")
        print(f"{label}_p50_ms={statistics.median(values):.6f}")
        print(f"{label}_p95_ms={pct(values, 0.95):.6f}")
        print(f"{label}_max_ms={max(values):.6f}")

    print(f"rss_final_mb={rss_mb():.3f}")
    print(f"cuda_alloc_final_mb={torch.cuda.memory_allocated() / 1024**2:.3f}")
    print(f"cuda_peak_final_mb={torch.cuda.max_memory_allocated() / 1024**2:.3f}")
    print(f"cuda_reserved_final_mb={torch.cuda.memory_reserved() / 1024**2:.3f}")


if __name__ == "__main__":
    main()
