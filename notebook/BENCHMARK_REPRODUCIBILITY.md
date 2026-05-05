# Benchmark Reproducibility

This note defines how to reproduce the latency and memory rows used for the
GOOSEIDRS computational-performance table.

## Metrics

- **Latency** is single-frame prediction time after warm-up, reported in
  milliseconds per frame.
- **CPU latency** uses wall-clock time from `time.perf_counter_ns()`.
- **GPU latency** uses CUDA events for GPU execution time. Tree models use
  RAPIDS FIL; neural models use PyTorch CUDA.
- **Memory** is process resident set size (RSS) in MB after model/runtime
  initialization. It is not the serialized model size.
- Benchmarks run one model per process to avoid carrying runtime memory from
  one model into another.

These measurements characterize an external monitoring node or substation
gateway. They are not direct benchmarks on vendor IED firmware.

## CPU Benchmarks

Run from the repository root with the Python environment used for the paper:

```powershell
.\.venv\Scripts\python.exe notebook\run_benchmark_suite.py --mode cpu --output-dir benchmark_results\cpu
```

The CPU suite accepts `--warmup` and `--reps` if a different repetition count is
needed.

To run only the deployed LightGBM IDRS model:

```powershell
.\.venv\Scripts\python.exe notebook\benchmark_cpu_models.py lgbm_idrs --output-dir benchmark_results\cpu
```

The individual CPU script also accepts:

```powershell
.\.venv\Scripts\python.exe notebook\benchmark_cpu_models.py all --warmup 100 --reps 2000 --output-dir benchmark_results\cpu
```

Each CPU run writes a JSON file with package versions, CPU/RAM metadata,
serialized artifact size, timing percentiles, and RSS memory. When run through
the suite, these JSON files are stored under `benchmark_results/cpu/json`.
The default CPU suite excludes Mamba because the local Windows environment does
not include `mamba-ssm`; run `benchmark_cpu_models.py mamba` explicitly in an
environment that supports it.

## GPU Benchmarks

Run inside the existing WSL conda environment:

```bash
cd /mnt/c/Users/herme/OneDrive/Documents/goose-idrs/goose-idrs
source ~/miniconda3/etc/profile.d/conda.sh
conda activate rapids-24.10
python notebook/run_benchmark_suite.py --mode gpu --output-dir benchmark_results/gpu
```

To run only the deployed LightGBM IDRS model through RAPIDS FIL:

```bash
python notebook/benchmark_gpu_only_models.py lgbm_idrs_fil
```

The GPU suite captures one stdout/stderr log per model plus a `manifest.json`
with Python, package, and CUDA metadata.

## Reporting Guidance

When adding the benchmark table to the paper, include the benchmark scope in the
caption:

> Latency is mean single-frame inference time after warm-up. Memory is process
> RSS after model/runtime initialization. Tree-model GPU inference uses RAPIDS
> FIL; neural GPU inference uses PyTorch CUDA. Measurements were obtained on an
> external monitoring/gateway host and do not represent direct IED-firmware
> execution.

If reporting the deployed GOOSEIDRS detector, use the `lgbm_idrs` CPU result or
the `lgbm_idrs_fil` GPU result. If reporting the notebook comparison model, use
`lgbm_opt` or `lgbm_opt_fil` and label it separately.
