"""
attack_perf_test.py

Performance benchmarking for attack scenarios.

Measures:
  - Time to execute each attack scenario
  - Whether rejection/containment happened as expected
  - Skipped cases if servers are intentionally offline
"""

import json
import sys
import time
from typing import List, Dict

# Add project root to path
sys.path.insert(0, '.')

from attacks import (
    attack_1_single_malicious_authority,
    attack_2_modified_ticket_payload,
    attack_3_replay_old_partial_signature,
    attack_4_one_key_leakage,
    attack_5_authority_offline,
    attack_6_single_valid_signature,
    find_tgs_base,
    PASS,
    FAIL,
    SKIP,
)


class AttackBenchmark:
    """Track attack performance metrics."""

    def __init__(self):
        self.results: List[Dict] = []

    def measure_attack(self, attack_name: str, attack_func, tgs_base: str,
                      expected: str = "REJECTED") -> Dict:
        """
        Measure single attack execution.
        
        Args:
            attack_name: Name of attack (e.g., "Attack 1")
            attack_func: Function to call
            tgs_base: Base URL for TGS
            expected: Expected outcome ("REJECTED", "ACCEPTED", "SKIPPED")
        
        Returns:
            Dict with timing and result info
        """
        print(f"  {attack_name}...", end=" ", flush=True)

        start = time.perf_counter()
        try:
            # Capture stdout to check for PASS/FAIL/SKIP indicators
            import io
            from contextlib import redirect_stdout

            capture = io.StringIO()
            with redirect_stdout(capture):
                attack_func(tgs_base)

            elapsed_ms = (time.perf_counter() - start) * 1000
            output = capture.getvalue()

            # Determine result from output
            if SKIP in output:
                result = "SKIPPED"
                status = "⚠️"
            elif PASS in output:
                result = "CONTAINED" if expected != "ACCEPTED" else "ACCEPTED"
                status = "✅"
            elif FAIL in output:
                result = "FAILED"
                status = "❌"
            else:
                result = "UNKNOWN"
                status = "❓"

            print(f"{status} {elapsed_ms:.2f}ms ({result})")

            return {
                "attack": attack_name,
                "elapsed_ms": round(elapsed_ms, 2),
                "expected": expected,
                "actual": result,
                "passed": (result == expected or (expected == "REJECTED" and result == "CONTAINED")),
                "output_snippet": output[:100] if output else ""
            }

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            print(f"❌ {elapsed_ms:.2f}ms (ERROR: {e})")
            return {
                "attack": attack_name,
                "elapsed_ms": round(elapsed_ms, 2),
                "expected": expected,
                "actual": "ERROR",
                "passed": False,
                "error": str(e)
            }

    def benchmark_all_attacks(self, tgs_base: str, num_runs: int = 1) -> List[Dict]:
        """Run all attack scenarios."""
        attacks = [
            ("Attack 1: Single Malicious Authority", attack_1_single_malicious_authority, "REJECTED"),
            ("Attack 2: Modified Ticket Payload", attack_2_modified_ticket_payload, "REJECTED"),
            ("Attack 3: Replay Old Partial Sig", attack_3_replay_old_partial_signature, "REJECTED"),
            ("Attack 4: One Key Leakage", attack_4_one_key_leakage, "REJECTED"),
            ("Attack 5: Authority Offline", attack_5_authority_offline, "ACCEPTED"),
            ("Attack 6: Single Signature Only", attack_6_single_valid_signature, "REJECTED"),
        ]

        all_results = []

        for run_num in range(num_runs):
            if num_runs > 1:
                print(f"\n{'─'*80}")
                print(f"Run {run_num + 1}/{num_runs}")
                print(f"{'─'*80}")

            for attack_name, attack_func, expected in attacks:
                result = self.measure_attack(attack_name, attack_func, tgs_base, expected)
                all_results.append(result)

        self.results = all_results
        return all_results

    def get_stats(self) -> Dict:
        """Calculate aggregate statistics."""
        if not self.results:
            return {}

        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        rejected = sum(1 for r in self.results if r["actual"] == "CONTAINED")
        accepted = sum(1 for r in self.results if r["actual"] == "ACCEPTED")
        skipped = sum(1 for r in self.results if r["actual"] == "SKIPPED")
        errors = sum(1 for r in self.results if r["actual"] == "ERROR")

        timings = [r["elapsed_ms"] for r in self.results if r["elapsed_ms"] > 0]

        return {
            "total_attacks": total,
            "passed": passed,
            "pass_rate": f"{100*passed//total}%" if total > 0 else "0%",
            "contained": rejected,
            "accepted": accepted,
            "skipped": skipped,
            "errors": errors,
            "avg_latency_ms": round(sum(timings) / len(timings), 2) if timings else 0,
            "min_latency_ms": round(min(timings), 2) if timings else 0,
            "max_latency_ms": round(max(timings), 2) if timings else 0,
        }

    def print_summary(self):
        """Print summary report."""
        stats = self.get_stats()

        print("\n" + "=" * 100)
        print("ATTACK PERFORMANCE SUMMARY")
        print("=" * 100)

        print(f"\nOverall Results:")
        print(f"  Total Attacks:    {stats['total_attacks']}")
        print(f"  Passed:           {stats['passed']}/{stats['total_attacks']} ({stats['pass_rate']})")
        print(f"  Contained:        {stats['contained']}")
        print(f"  Accepted:         {stats['accepted']}")
        print(f"  Skipped:          {stats['skipped']}")
        print(f"  Errors:           {stats['errors']}")

        print(f"\nPerformance:")
        print(f"  Average Latency:  {stats['avg_latency_ms']} ms")
        print(f"  Min Latency:      {stats['min_latency_ms']} ms")
        print(f"  Max Latency:      {stats['max_latency_ms']} ms")

        print("\nDetailed Results:")
        print(f"{'Attack':<40} {'Time (ms)':<12} {'Expected':<12} {'Actual':<12} {'Status':<6}")
        print(f"{'─'*40} {'─'*12} {'─'*12} {'─'*12} {'─'*6}")

        for result in self.results:
            status = "✅" if result["passed"] else "❌"
            print(
                f"{result['attack']:<40} {result['elapsed_ms']:<12} "
                f"{result['expected']:<12} {result['actual']:<12} {status:<6}"
            )

        print("=" * 100)


def main():
    print("\n" + "=" * 100)
    print(" ATTACK SCENARIO PERFORMANCE BENCHMARK")
    print("=" * 100 + "\n")

    # Find TGS endpoint
    print("Finding TGS endpoint...")
    tgs_base = find_tgs_base()

    if not tgs_base:
        print("\n❌ ERROR: No TGS endpoint reachable.")
        print("   Make sure TGS servers are running on ports 6001-6003")
        print("   Start with: python tgs_node.py TGS1 6001 (in separate terminal)")
        sys.exit(1)

    print(f"✅ Found TGS at {tgs_base}\n")

    # Run benchmarks
    benchmark = AttackBenchmark()

    print(f"{'─'*80}")
    print("Running Attack Scenarios")
    print(f"{'─'*80}\n")

    benchmark.benchmark_all_attacks(tgs_base, num_runs=1)

    # Print results
    benchmark.print_summary()

    # Save to JSON
    results_json = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "tgs_endpoint": tgs_base,
        "stats": benchmark.get_stats(),
        "attacks": benchmark.results
    }

    filename = "attack_perf_results.json"
    with open(filename, "w") as f:
        json.dump(results_json, f, indent=2)

    print(f"\n✅ Detailed results saved to {filename}\n")


if __name__ == "__main__":
    main()
