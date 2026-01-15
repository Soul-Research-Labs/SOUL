import { ethers } from "ethers";

export interface StakingConfig {
  minStake: number;
  slashingRate: number;
  rewardRate: number;
}

export interface Stake {
  relayerId: string;
  amount: number;
  lockedUntil: number;
}

export class StakingManager {
  private stakes: Map<string, Stake> = new Map();

  constructor(public config: StakingConfig) {}

  async stake(relayerId: string, amount: number): Promise<boolean> {
    if (amount < this.config.minStake) {
      throw new Error(`Minimum stake is ${this.config.minStake}`);
    }
    const existing = this.stakes.get(relayerId) || { relayerId, amount: 0, lockedUntil: 0 };
    existing.amount += amount;
    existing.lockedUntil = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days lock
    this.stakes.set(relayerId, existing);
    return true;
  }

  async slash(relayerId: string, reason: string): Promise<number> {
    const stake = this.stakes.get(relayerId);
    if (!stake) return 0;
    const slashAmount = stake.amount * this.config.slashingRate;
    stake.amount -= slashAmount;
    this.stakes.set(relayerId, stake);
    console.log(`Slashed ${relayerId} for ${reason}: ${slashAmount}`);
    return slashAmount;
  }

  async reward(relayerId: string, successCount: number): Promise<number> {
    const stake = this.stakes.get(relayerId);
    if (!stake) return 0;
    const rewardAmount = successCount * this.config.rewardRate;
    stake.amount += rewardAmount;
    this.stakes.set(relayerId, stake);
    return rewardAmount;
  }

  getStake(relayerId: string): Stake | undefined {
    return this.stakes.get(relayerId);
  }
}
