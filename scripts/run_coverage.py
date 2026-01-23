#!/usr/bin/env python3
"""
PIL Coverage Runner v2

IMPORTANT: Forge coverage currently fails on this project due to "stack too deep"
errors in complex ZK verifier contracts. This is a known Foundry limitation.
See: https://github.com/foundry-rs/foundry/issues/3357

This script attempts to work around the issue by:
1. Backing up complex verifier contracts
2. Replacing them with simplified stubs (no assembly)
3. Running forge coverage
4. Restoring original contracts

LIMITATIONS:
- Even with stubs, other contracts may exceed stack limits
- Coverage report will not include stubbed contracts
- Results may be incomplete

For full test verification, use:
    forge test           # Unit/integration tests
    halmos               # Symbolic testing
    echidna              # Fuzz testing

Usage:
    python scripts/run_coverage.py [--report=summary|lcov|html]
    
Options:
    --report    Coverage report type (default: summary)
    --restore   Just restore backed up contracts (if interrupted)
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Project paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
BACKUP_DIR = PROJECT_DIR / ".coverage-backup"

# Mapping: original contract -> stub location
# Stubs must maintain the same public interface but without assembly
# Stubs are now stored OUTSIDE contracts folder to avoid compilation
STUB_MAPPING = {
    "contracts/verifiers/Groth16VerifierBLS12381.sol": "coverage-stubs/verifiers/Groth16VerifierBLS12381.sol",
    "contracts/verifiers/GasOptimizedVerifier.sol": "coverage-stubs/verifiers/GasOptimizedVerifier.sol",
    "contracts/verifiers/OptimizedGroth16Verifier.sol": "coverage-stubs/verifiers/OptimizedGroth16Verifier.sol",
    "contracts/verifiers/PLONKVerifier.sol": "coverage-stubs/verifiers/PLONKVerifier.sol",
    "contracts/verifiers/Groth16VerifierBN254.sol": "coverage-stubs/verifiers/Groth16VerifierBN254.sol",
    "contracts/verifiers/FRIVerifier.sol": "coverage-stubs/verifiers/FRIVerifier.sol",
    "contracts/core/Groth16VerifierBLS12381V2.sol": "coverage-stubs/core/Groth16VerifierBLS12381V2.sol",
}

# ANSI colors
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
CYAN = "\033[0;36m"
NC = "\033[0m"


def print_colored(msg: str, color: str = NC):
    print(f"{color}{msg}{NC}")


def backup_and_stub():
    """Backup original contracts and replace with stubs."""
    print_colored("\n📦 Backing up contracts and applying stubs...", CYAN)
    
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    success = 0
    for original, stub in STUB_MAPPING.items():
        original_path = PROJECT_DIR / original
        stub_path = PROJECT_DIR / stub
        backup_path = BACKUP_DIR / original
        
        if not original_path.exists():
            print_colored(f"  ⚠ Original not found: {original}", YELLOW)
            continue
            
        if not stub_path.exists():
            print_colored(f"  ⚠ Stub not found: {stub}", YELLOW)
            continue
        
        # Backup original
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(original_path), str(backup_path))
        
        # Replace with stub
        shutil.copy2(str(stub_path), str(original_path))
        
        success += 1
        print(f"  ✓ Replaced: {original}")
    
    print_colored(f"\n✓ Replaced {success} contracts with stubs.", GREEN)
    return success


def restore_contracts():
    """Restore backed up contracts."""
    print_colored("\n🔄 Restoring original contracts...", CYAN)
    
    if not BACKUP_DIR.exists():
        print_colored("No backup directory found.", YELLOW)
        return
    
    restored = 0
    for original in STUB_MAPPING.keys():
        backup_path = BACKUP_DIR / original
        original_path = PROJECT_DIR / original
        
        if backup_path.exists():
            shutil.copy2(str(backup_path), str(original_path))
            restored += 1
            print(f"  ✓ Restored: {original}")
    
    # Clean up backup directory
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    
    print_colored(f"\n✓ Restored {restored} contracts.", GREEN)


def run_coverage(report_type: str = "summary"):
    """Run forge coverage with proper error handling."""
    print_colored("\n🔍 Running forge coverage...", CYAN)
    
    cmd = [
        "forge", "coverage",
        "--ir-minimum",
        f"--report={report_type}"
    ]
    
    # Optionally skip tests that use the stubbed contracts
    # Add patterns to exclude problematic tests
    cmd.extend([
        "--no-match-test", "testBLS12381|testOptimizedGroth16|testPLONK|testFRI|testBN254Verifier"
    ])
    
    print(f"  Running: {' '.join(cmd)}")
    print()
    
    result = subprocess.run(
        cmd,
        cwd=str(PROJECT_DIR),
        env={**os.environ, "FOUNDRY_PROFILE": "coverage"}
    )
    
    return result.returncode


def main():
    """Main entry point."""
    args = sys.argv[1:]
    
    # Parse arguments
    report_type = "summary"
    restore_only = False
    
    for arg in args:
        if arg.startswith("--report="):
            report_type = arg.split("=")[1]
        elif arg == "--restore":
            restore_only = True
    
    print_colored("=" * 60, CYAN)
    print_colored("   PIL Coverage Runner v2", CYAN)
    print_colored("=" * 60, CYAN)
    
    # Just restore if requested
    if restore_only:
        restore_contracts()
        return 0
    
    try:
        # Step 1: Backup and apply stubs
        count = backup_and_stub()
        if count == 0:
            print_colored("\n❌ No contracts were stubbed. Check paths.", RED)
            return 1
        
        # Step 2: Run coverage
        exit_code = run_coverage(report_type)
        
        if exit_code == 0:
            print_colored("\n✅ Coverage completed successfully!", GREEN)
        else:
            print_colored(f"\n⚠ Coverage exited with code {exit_code}", YELLOW)
        
        return exit_code
        
    except KeyboardInterrupt:
        print_colored("\n\n⚠ Interrupted by user", YELLOW)
        return 130
        
    except Exception as e:
        print_colored(f"\n❌ Error: {e}", RED)
        return 1
        
    finally:
        # Always restore contracts
        restore_contracts()


if __name__ == "__main__":
    sys.exit(main())
