#!/usr/bin/env python3
"""
generate_report.py — Generates mutation-test-report.csv evidence
containing all 42 per-technique mutation test results.
"""

import os
import csv
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from pipeline.mutation_testing import run_all_mutations
except ImportError:
    print("[-] Error: Could not import pipeline.mutation_testing module.")
    sys.exit(1)

def main():
    print("[*] Evaluating 42 per-technique mutation contract checks...")
    results = run_all_mutations()
    
    # Validation constraint sanity check
    assert len(results) == 42, f"Expected 42 total checks, got {len(results)}"
    
    output_file = "mutation-test-report.csv"
    headers = ["technique", "dimension", "expected", "actual", "verdict"]
    
    print(f"[*] Exporting matrix entries into {output_file}...")
    with open(output_file, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for res in results:
            verdict_str = "PASS" if res.passed else "FAIL"
            writer.writerow([
                res.technique_id,
                res.dimension,
                res.expected,
                res.actual,
                verdict_str
            ])
            
    print(f"[+] Success: Generated {len(results)} rows inside the mutation test report matrix.")

if __name__ == "__main__":
    main()
