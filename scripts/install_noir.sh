#!/bin/bash

# Setup Noir (nargo)
if ! command -v nargo &> /dev/null; then
    echo "Installing Noir (nargo)..."
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
    export PATH="$HOME/.nargo/bin:$PATH"
    noirup
else
    echo "Noir (nargo) already installed: $(nargo --version)"
fi

# Setup Barretenberg (bb)
if ! command -v bb &> /dev/null; then
    echo "Installing Barretenberg (bb)..."
    curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash
    export PATH="$HOME/.bb/bin:$PATH"
    bbup
else
    echo "Barretenberg (bb) already installed: $(bb --version)"
fi

echo "Noir toolchain setup complete."
