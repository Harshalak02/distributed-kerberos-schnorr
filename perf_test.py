"""
perf_test.py

Performance benchmarking for Kerberos multi-signature system.

Measures:
  - Phase 1 latency (Client → AS cluster → TGT assembled)
  - Phase 2 latency (Client → TGS cluster → ST assembled)
  - Phase 3 latency (Client → Service access response)
  - End-to-end latency (Phase 1 + Phase 2 + Phase 3)
  - Success rate (runs passed / total)

Scenarios:
  - All 3 authorities online
  - AS1 offline (2-of-3 fallback)
  - TGS1 offline (2-of-3 fallback)
"""

import json
import sys
import time
from typing import List, Dict, Tuple

# Add project root to path
sys.path.insert(0, '.')

from client import (
    load_public_registry,
    obtain_tgt,
    obtain_service_ticket,
    access_service,
)


class PerformanceMetrics:
    """Collect and report performance metrics."""

    def __init__(self, scenario_name: str):
        self.scenario_name = scenario_name
        self.runs: List[Dict] = []

    def add_run(self, phase1_ms: float, phase2_ms: float, phase3_ms: float,
                success: bool, error: str = None):
        """Add a single benchmark run."""
        total_ms = phase1_ms + phase2_ms + phase3_ms
        self.runs.append({
            "phase1_ms": round(phase1_ms, 2),
            "phase2_ms": round(phase2_ms, 2),
            "phase3_ms": round(phase3_ms, 2),
            "total_ms": round(total_ms, 2),
            "success": success,
            "error": error
        })

    def get_stats(self) -> Dict:
        """Calculate aggregate statistics."""
        successful = [r for r in self.runs if r["success"]]
        
        if not successful:
            return {
                "scenario": self.scenario_name,
                "total_runs": len(self.runs),
                "successful_runs": 0,
                "success_rate": "0%",
                "phase1_ms": {"avg": None, "min": None, "max": None},
                "phase2_ms": {"avg": None, "min": None, "max": None},
                "phase3_ms": {"avg": None, "min": None, "max": None},
                "total_ms": {"avg": None, "min": None, "max": None},
            }

        p1_times = [r["phase1_ms"] for r in successful]
        p2_times = [r["phase2_ms"] for r in successful]
        p3_times = [r["phase3_ms"] for r in successful]
        total_times = [r["total_ms"] for r in successful]

        return {
            "scenario": self.scenario_name,
            "total_runs": len(self.runs),
            "successful_runs": len(successful),
            "success_rate": f"{len(successful)}/{len(self.runs)} ({100*len(successful)//len(self.runs)}%)",
            "phase1_ms": {
                "avg": round(sum(p1_times) / len(p1_times), 2),
                "min": round(min(p1_times), 2),
                "max": round(max(p1_times), 2),
            },
            "phase2_ms": {
                "avg": round(sum(p2_times) / len(p2_times), 2),
                "min": round(min(p2_times), 2),
                "max": round(max(p2_times), 2),
            },
            "phase3_ms": {
                "avg": round(sum(p3_times) / len(p3_times), 2),
                "min": round(min(p3_times), 2),
                "max": round(max(p3_times), 2),
            },
            "total_ms": {
                "avg": round(sum(total_times) / len(total_times), 2),
                "min": round(min(total_times), 2),
                "max": round(max(total_times), 2),
            },
        }


def measure_single_run(client_id: str, service_id: str) -> Tuple[float, float, float, bool, str]:
    """
    Measure a single complete authentication flow.
    Returns: (phase1_ms, phase2_ms, phase3_ms, success, error_msg)
    """
    try:
        # Load registry once
        public_registry = load_public_registry()

        # Phase 1: TGT assembly
        phase1_start = time.perf_counter()
        tgt = obtain_tgt(client_id, public_registry)
        phase1_ms = (time.perf_counter() - phase1_start) * 1000

        # Phase 2: Service ticket assembly
        phase2_start = time.perf_counter()
        service_ticket, service_session_key = obtain_service_ticket(
            client_id, service_id, tgt, public_registry
        )
        phase2_ms = (time.perf_counter() - phase2_start) * 1000

        # Phase 3: Service access
        phase3_start = time.perf_counter()
        result = access_service(client_id, service_id, service_ticket, service_session_key)
        phase3_ms = (time.perf_counter() - phase3_start) * 1000

        success = result.get("status") == "ACCESS GRANTED"
        error = None if success else result.get("error", "Unknown error")

        return phase1_ms, phase2_ms, phase3_ms, success, error

    except Exception as e:
        return 0, 0, 0, False, str(e)


def benchmark_scenario(scenario_name: str, client_base: str, service_id: str,
                       num_runs: int = 3, verbose: bool = True) -> PerformanceMetrics:
    """
    Run benchmark for a specific scenario.
    
    Args:
        scenario_name: Description of scenario (e.g., "All Online", "AS1 Offline")
        client_base: Base client name (will append run number)
        service_id: Target service
        num_runs: Number of runs to perform
        verbose: Print per-run status
    
    Returns:
        PerformanceMetrics object with collected data
    """
    metrics = PerformanceMetrics(scenario_name)

    if verbose:
        print(f"\n{'─' * 80}")
        print(f"Scenario: {scenario_name}")
        print(f"{'─' * 80}")

    for run_num in range(num_runs):
        client_id = f"{client_base}_run{run_num+1}"
        
        if verbose:
            print(f"  Run {run_num+1}/{num_runs}...", end=" ", flush=True)

        phase1_ms, phase2_ms, phase3_ms, success, error = measure_single_run(
            client_id, service_id
        )

        metrics.add_run(phase1_ms, phase2_ms, phase3_ms, success, error)

        if verbose:
            if success:
                total_ms = phase1_ms + phase2_ms + phase3_ms
                print(f"✅ {total_ms:.0f}ms total (P1:{phase1_ms:.0f}ms | P2:{phase2_ms:.0f}ms | P3:{phase3_ms:.0f}ms)")
            else:
                print(f"❌ FAILED: {error}")

    return metrics


def print_comparison_table(metrics_list: List[PerformanceMetrics]):
    """Print comparison table for multiple scenarios."""
    print("\n" + "=" * 100)
    print("PERFORMANCE COMPARISON")
    print("=" * 100)

    # Header
    print(f"\n{'Scenario':<25} {'Phase 1 (ms)':<15} {'Phase 2 (ms)':<15} {'Phase 3 (ms)':<15} {'Total (ms)':<15} {'Success':<12}")
    print(f"{'─'*25} {'─'*15} {'─'*15} {'─'*15} {'─'*15} {'─'*12}")

    # Row per scenario
    for metrics in metrics_list:
        stats = metrics.get_stats()
        
        p1_str = f"{stats['phase1_ms']['avg']}" if stats['phase1_ms']['avg'] else "N/A"
        p2_str = f"{stats['phase2_ms']['avg']}" if stats['phase2_ms']['avg'] else "N/A"
        p3_str = f"{stats['phase3_ms']['avg']}" if stats['phase3_ms']['avg'] else "N/A"
        total_str = f"{stats['total_ms']['avg']}" if stats['total_ms']['avg'] else "N/A"

        print(f"{metrics.scenario_name:<25} {p1_str:<15} {p2_str:<15} {p3_str:<15} {total_str:<15} {stats['success_rate']:<12}")

    print("=" * 100)


def print_detailed_stats(metrics: PerformanceMetrics):
    """Print detailed statistics for a single scenario."""
    stats = metrics.get_stats()

    print(f"\n{'─' * 80}")
    print(f"Detailed Statistics: {metrics.scenario_name}")
    print(f"{'─' * 80}")

    if stats['successful_runs'] == 0:
        print("❌ No successful runs in this scenario.")
        for run in metrics.runs:
            print(f"  Run {metrics.runs.index(run)+1}: {run['error']}")
        return

    print(f"\nSuccess Rate: {stats['success_rate']}")
    print(f"\nPhase 1 (TGT Assembly):")
    print(f"  Average: {stats['phase1_ms']['avg']}ms")
    print(f"  Min:     {stats['phase1_ms']['min']}ms")
    print(f"  Max:     {stats['phase1_ms']['max']}ms")

    print(f"\nPhase 2 (Service Ticket Assembly):")
    print(f"  Average: {stats['phase2_ms']['avg']}ms")
    print(f"  Min:     {stats['phase2_ms']['min']}ms")
    print(f"  Max:     {stats['phase2_ms']['max']}ms")

    print(f"\nPhase 3 (Service Access):")
    print(f"  Average: {stats['phase3_ms']['avg']}ms")
    print(f"  Min:     {stats['phase3_ms']['min']}ms")
    print(f"  Max:     {stats['phase3_ms']['max']}ms")

    print(f"\nEnd-to-End Latency:")
    print(f"  Average: {stats['total_ms']['avg']}ms")
    print(f"  Min:     {stats['total_ms']['min']}ms")
    print(f"  Max:     {stats['total_ms']['max']}ms")


def main():
    print("\n" + "=" * 100)
    print(" KERBEROS MULTI-SIGNATURE PERFORMANCE BENCHMARK")
    print("=" * 100)

    # Scenario 1: All authorities online
    metrics_online = benchmark_scenario(
        "All Authorities Online (3-of-3)",
        "perf_all_online",
        "file_server",
        num_runs=3,
        verbose=True
    )

    # Scenario 2: AS1 offline (2-of-3 fallback)
    print("\n" + "─" * 100)
    print("⚠️  Next scenario requires AS1 to be OFFLINE")
    print("    Kill AS1 process (port 5001), then press ENTER to continue...")
    print("    Or just press ENTER to skip this scenario.")
    try:
        user_input = input("    Ready? (y/n): ").strip().lower()
        if user_input == 'y':
            metrics_as1_down = benchmark_scenario(
                "AS1 Offline (2-of-3 fallback)",
                "perf_as1_down",
                "file_server",
                num_runs=3,
                verbose=True
            )
        else:
            print("    Skipping AS1 offline scenario...")
            metrics_as1_down = None
    except KeyboardInterrupt:
        print("\n    Skipping AS1 offline scenario...")
        metrics_as1_down = None

    # Scenario 3: TGS1 offline (2-of-3 fallback)
    print("\n" + "─" * 100)
    print("⚠️  Next scenario requires TGS1 to be OFFLINE")
    print("    Kill TGS1 process (port 6001), then press ENTER to continue...")
    print("    Or just press ENTER to skip this scenario.")
    try:
        user_input = input("    Ready? (y/n): ").strip().lower()
        if user_input == 'y':
            metrics_tgs1_down = benchmark_scenario(
                "TGS1 Offline (2-of-3 fallback)",
                "perf_tgs1_down",
                "file_server",
                num_runs=3,
                verbose=True
            )
        else:
            print("    Skipping TGS1 offline scenario...")
            metrics_tgs1_down = None
    except KeyboardInterrupt:
        print("\n    Skipping TGS1 offline scenario...")
        metrics_tgs1_down = None

    # Print results
    print("\n" + "=" * 100)
    print("RESULTS SUMMARY")
    print("=" * 100)

    # Detailed stats for each scenario
    print_detailed_stats(metrics_online)

    if metrics_as1_down:
        print_detailed_stats(metrics_as1_down)

    if metrics_tgs1_down:
        print_detailed_stats(metrics_tgs1_down)

    # Comparison table
    all_metrics = [metrics_online]
    if metrics_as1_down:
        all_metrics.append(metrics_as1_down)
    if metrics_tgs1_down:
        all_metrics.append(metrics_tgs1_down)

    print_comparison_table(all_metrics)

    # Save results to JSON
    results = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "scenarios": []
    }

    for metrics in all_metrics:
        results["scenarios"].append({
            "name": metrics.scenario_name,
            "stats": metrics.get_stats(),
            "runs": metrics.runs
        })

    filename = "perf_results.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Detailed results saved to {filename}")
    print("\n" + "=" * 100)


if __name__ == "__main__":
    main()
