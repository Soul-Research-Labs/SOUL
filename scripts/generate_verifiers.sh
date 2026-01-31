#!/bin/bash

# Ensure toolchain is in PATH
export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

GENERATED_DIR="contracts/verifiers/generated"
mkdir -p "$GENERATED_DIR"

# Loop through all noir circuits
for circuit_dir in noir/*; do
    if [ -d "$circuit_dir" ] && [ -f "$circuit_dir/Nargo.toml" ]; then
        circuit_name=$(basename "$circuit_dir")
        echo "Processing circuit: $circuit_name"
        
        cd "$circuit_dir"
        
        # Compile
        nargo compile
        
        # Generate Verifier
        # Note: 'codegen-verifier' is the nargo command, but 'bb' is often used for UltraPlonk
        # We will try nargo's built-in first
        nargo codegen-verifier
        
        # Move and rename
        if [ -f "contract/plonk_vk.sol" ]; then
            # Handle standard nargo output
            target_name="${circuit_name^}Verifier.sol"
            # Basic string replacement for contract name
            sed "s/UltraVerifier/${circuit_name^}Verifier/g" contract/plonk_vk.sol > "../../$GENERATED_DIR/$target_name"
            echo "Generated $target_name"
        elif [ -f "target/verifier.sol" ]; then
             target_name="${circuit_name^}Verifier.sol"
             sed "s/UltraVerifier/${circuit_name^}Verifier/g" target/verifier.sol > "../../$GENERATED_DIR/$target_name"
             echo "Generated $target_name"
        fi
        
        cd ../..
    fi
done

echo "Noir verifier generation complete."
