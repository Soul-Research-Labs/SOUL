import { ethers } from "ethers";

export interface PILClientOptions {
  chainId: number;
  signer: ethers.Signer;
  addresses: Record<string, string>;
}

export class PILClient {
  constructor(public options: PILClientOptions) {}

  async registerPrivateState(stateHash: string, proofType: number) {
    // Call contract to register private state
  }

  async bridgeProof({ destChain, proof, nullifier }: { destChain: number; proof: string; nullifier: string }) {
    // Call bridge contract to relay proof
  }

  compliance = {
    async checkKYC(address: string): Promise<boolean> {
      // Call compliance contract
      return true;
    },
  };
}
