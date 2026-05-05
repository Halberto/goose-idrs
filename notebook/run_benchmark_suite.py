import argparse
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CPU_MODELS = ("rf", "xgb", "lgbm_idrs", "lgbm_opt", "gru", "transformer")
GPU_MODELS = ("rf_fil", "xgb_fil", "lgbm_idrs_fil", "lgbm_opt_fil", "gru", "mamba", "transformer")


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
        "cuml": package_version("cuml"),
        "cupy-cuda12x": package_version("cupy-cuda12x"),
    }
    gpu = None
    try:
        import torch

        gpu = {
            "cuda_available": torch.cuda.is_available(),
            "torch_cuda": torch.version.cuda,
            "device": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        }
    except Exception as exc:
        gpu = {"error": repr(exc)}
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cwd": str(REPO_ROOT),
        "packages": packages,
        "gpu": gpu,
    }


def default_output_dir(mode):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPO_ROOT / "benchmark_results" / f"{mode}_{stamp}"


def run_one(script, model, output_dir, mode, warmup, reps):
    stdout_path = output_dir / f"{model}.stdout.txt"
    stderr_path = output_dir / f"{model}.stderr.txt"
    command = [sys.executable, str(script), model]
    if mode == "cpu":
        command.extend(["--warmup", str(warmup), "--reps", str(reps), "--output-dir", str(output_dir / "json")])
    start = time.perf_counter()
    completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True)
    duration_s = time.perf_counter() - start
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    return {
        "model": model,
        "command": command,
        "returncode": completed.returncode,
        "duration_s": duration_s,
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


def main():
    parser = argparse.ArgumentParser(description="Run saved-model runtime benchmarks in fresh processes.")
    parser.add_argument("--mode", choices=("cpu", "gpu"), required=True)
    parser.add_argument("--models", nargs="+", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--warmup", type=int, default=100, help="CPU-only warm-up iterations.")
    parser.add_argument("--reps", type=int, default=2000, help="CPU-only benchmark repetitions.")
    args = parser.parse_args()

    if args.mode == "cpu":
        script = REPO_ROOT / "notebook" / "benchmark_cpu_models.py"
        models = args.models or list(CPU_MODELS)
    else:
        script = REPO_ROOT / "notebook" / "benchmark_gpu_only_models.py"
        models = args.models or list(GPU_MODELS)

    output_dir = Path(args.output_dir) if args.output_dir else default_output_dir(args.mode)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "mode": args.mode,
        "script": str(script),
        "models": models,
        "warmup": args.warmup if args.mode == "cpu" else None,
        "reps": args.reps if args.mode == "cpu" else None,
        "environment": environment_metadata(),
        "runs": [],
    }
    for model in models:
        print(f"benchmarking {model}")
        run = run_one(script, model, output_dir, args.mode, args.warmup, args.reps)
        manifest["runs"].append(run)
        print(f"  returncode={run['returncode']} stdout={run['stdout']}")

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"manifest={manifest_path}")

    failures = [run["model"] for run in manifest["runs"] if run["returncode"]]
    if failures:
        raise SystemExit(f"benchmark failures: {', '.join(failures)}")


if __name__ == "__main__":
    main()
