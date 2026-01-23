"""
PIL Protocol Game Theory Simulations
Economic security analysis and attack modeling
Author: PIL Protocol Team
Date: January 2026
"""

import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import math


class ActorType(Enum):
    HONEST_OPERATOR = "honest_operator"
    RATIONAL_ATTACKER = "rational_attacker"
    GRIEFING_ATTACKER = "griefing_attacker"
    COLLUDING_OPERATOR = "colluding_operator"


class AttackType(Enum):
    DOUBLE_SPEND = "double_spend"
    PROOF_FORGERY = "proof_forgery"
    GRIEFING = "griefing"
    COLLUSION = "collusion"
    FLASH_LOAN = "flash_loan"
    MEV_EXTRACTION = "mev_extraction"


@dataclass
class Actor:
    """Represents a participant in the protocol"""
    id: str
    actor_type: ActorType
    capital: float
    bond: float = 0.0
    reputation: float = 5000.0  # 0-10000
    successful_ops: int = 0
    failed_ops: int = 0
    slashed_amount: float = 0.0
    
    @property
    def is_rational(self) -> bool:
        return self.actor_type in [ActorType.RATIONAL_ATTACKER, ActorType.HONEST_OPERATOR]


@dataclass
class ProtocolState:
    """Current state of the protocol"""
    tvl: float
    insurance_fund: float
    total_operator_bonds: float
    min_bond: float = 1.0  # ETH
    slashing_ratio: float = 0.5  # 50%
    attack_cost: float = 0.1  # ETH
    max_profit_ratio: float = 0.01  # 1% of TVL
    
    @property
    def max_profit(self) -> float:
        return self.tvl * self.max_profit_ratio


@dataclass
class SimulationResult:
    """Results from a simulation run"""
    scenario: str
    attacks_attempted: int = 0
    attacks_successful: int = 0
    total_slashed: float = 0.0
    total_losses: float = 0.0
    insurance_claims: float = 0.0
    honest_operator_profit: float = 0.0
    attacker_profit: float = 0.0
    is_economically_secure: bool = True
    details: Dict = field(default_factory=dict)


class BridgeAttackSimulation:
    """
    Simulate various attack scenarios on PIL bridge
    Model rational attacker behavior and verify economic security
    """
    
    def __init__(self, protocol_state: ProtocolState):
        self.state = protocol_state
        self.actors: List[Actor] = []
        self.history: List[Dict] = []
    
    def add_actor(self, actor: Actor):
        """Add an actor to the simulation"""
        self.actors.append(actor)
    
    def simulate_attacker_strategy(
        self, 
        attacker: Actor,
        attack_type: AttackType
    ) -> Tuple[bool, float, str]:
        """
        Model rational attacker with capital X
        Returns: (should_attack, expected_profit, reason)
        """
        # Calculate attack cost
        attack_cost = self.state.attack_cost
        required_bond = self.state.min_bond
        
        # Calculate potential profit
        if attack_type == AttackType.DOUBLE_SPEND:
            potential_profit = self.state.max_profit
            success_probability = 0.1  # 10% if we have proper security
            
        elif attack_type == AttackType.PROOF_FORGERY:
            potential_profit = self.state.max_profit * 0.5
            success_probability = 0.05  # Very low with proper verification
            
        elif attack_type == AttackType.GRIEFING:
            potential_profit = 0  # No profit, only damage
            success_probability = 0.3
            
        elif attack_type == AttackType.COLLUSION:
            # Requires multiple actors
            colluding_actors = [a for a in self.actors 
                              if a.actor_type == ActorType.COLLUDING_OPERATOR]
            if len(colluding_actors) < 3:
                return (False, 0, "Insufficient colluders")
            potential_profit = self.state.max_profit * 2
            success_probability = 0.2
            
        elif attack_type == AttackType.FLASH_LOAN:
            potential_profit = self.state.tvl * 0.02  # 2% of TVL
            success_probability = 0.01  # Very low with flash loan guard
            
        elif attack_type == AttackType.MEV_EXTRACTION:
            potential_profit = self.state.tvl * 0.001  # 0.1% of TVL
            success_probability = 0.05  # Low with commit-reveal
        
        else:
            return (False, 0, "Unknown attack type")
        
        # Calculate expected value
        slashing_loss = required_bond * self.state.slashing_ratio
        
        expected_profit = (
            (potential_profit * success_probability) - 
            (slashing_loss * (1 - success_probability)) -
            attack_cost
        )
        
        # Rational attacker only attacks if expected profit > 0
        should_attack = expected_profit > 0 and attacker.is_rational
        
        reason = f"EV: {expected_profit:.4f} ETH (profit: {potential_profit:.2f}, " \
                 f"prob: {success_probability:.2%}, slash: {slashing_loss:.2f})"
        
        return (should_attack, expected_profit, reason)
    
    def calculate_attack_cost(self, tvl: float) -> float:
        """
        Return minimum capital for profitable attack
        Based on slashing, attack cost, and success probability
        """
        # For attack to be profitable:
        # expected_profit > 0
        # profit * prob_success - slash * prob_fail - cost > 0
        
        max_profit = tvl * self.state.max_profit_ratio
        success_prob = 0.1  # Assume 10% with our security
        slash = self.state.min_bond * self.state.slashing_ratio
        cost = self.state.attack_cost
        
        # Solve for minimum profitable attack
        # profit * 0.1 - slash * 0.9 - cost > 0
        # profit > (slash * 0.9 + cost) / 0.1
        
        min_profitable_profit = (slash * 0.9 + cost) / success_prob
        
        # If max_profit < min_profitable_profit, attack is never profitable
        if max_profit < min_profitable_profit:
            return float('inf')
        
        return self.state.min_bond + cost
    
    def verify_economic_security(self) -> Tuple[bool, str]:
        """
        Ensure cost_of_attack > potential_profit
        Returns: (is_secure, explanation)
        """
        attack_cost = self.calculate_attack_cost(self.state.tvl)
        max_profit = self.state.max_profit
        
        is_secure = attack_cost > max_profit
        
        explanation = (
            f"Attack cost: {attack_cost:.4f} ETH, "
            f"Max profit: {max_profit:.4f} ETH, "
            f"Ratio: {attack_cost/max_profit if max_profit > 0 else float('inf'):.2f}x"
        )
        
        return (is_secure, explanation)
    
    def simulate_collusion(
        self,
        colluders: List[Actor],
        target_value: float
    ) -> SimulationResult:
        """Simulate validator collusion scenarios"""
        result = SimulationResult(scenario="collusion")
        
        # Calculate combined bonds
        combined_bonds = sum(a.bond for a in colluders)
        
        # Calculate potential profit
        potential_profit = min(target_value, self.state.tvl * 0.1)
        
        # Calculate collusion success probability
        # Decreases with number of required colluders
        min_colluders = 3
        if len(colluders) < min_colluders:
            result.is_economically_secure = True
            result.details["reason"] = "Insufficient colluders"
            return result
        
        # Probability of being caught
        detection_prob = 1 - (0.9 ** len(colluders))  # Each colluder increases risk
        
        # Expected slashing
        expected_slash = combined_bonds * self.state.slashing_ratio * detection_prob
        
        # Expected profit per colluder
        profit_per_colluder = (potential_profit * (1 - detection_prob)) / len(colluders)
        
        # Is collusion profitable?
        result.attacker_profit = profit_per_colluder - (expected_slash / len(colluders))
        result.is_economically_secure = result.attacker_profit <= 0
        
        result.details = {
            "colluders": len(colluders),
            "combined_bonds": combined_bonds,
            "detection_prob": detection_prob,
            "expected_slash": expected_slash,
            "profit_per_colluder": profit_per_colluder
        }
        
        return result
    
    def calculate_minimum_viable_stake(self) -> float:
        """Calculate minimum stake for economic security"""
        # Minimum stake must ensure:
        # slashing_loss > max_profit
        
        max_profit = self.state.max_profit
        slashing_ratio = self.state.slashing_ratio
        
        # min_stake * slashing_ratio > max_profit
        # min_stake > max_profit / slashing_ratio
        
        min_stake = max_profit / slashing_ratio
        
        # Add safety margin
        min_stake *= 1.5
        
        return min_stake
    
    def verify_insurance_adequacy(self) -> Tuple[bool, float]:
        """Verify insurance fund adequacy"""
        # Insurance should cover worst case scenario
        # Worst case: all operators are slashed + maximum loss event
        
        worst_case_loss = self.state.max_profit * 10  # 10x max single loss
        
        coverage_ratio = self.state.insurance_fund / worst_case_loss
        is_adequate = coverage_ratio >= 1.0
        
        return (is_adequate, coverage_ratio)
    
    def run_monte_carlo(
        self,
        scenarios: int = 10000,
        attack_probability: float = 0.1
    ) -> Dict:
        """Run Monte Carlo simulation of attack scenarios"""
        results = {
            "total_scenarios": scenarios,
            "attacks_attempted": 0,
            "attacks_successful": 0,
            "total_slashed": 0.0,
            "total_losses": 0.0,
            "insurance_used": 0.0
        }
        
        for _ in range(scenarios):
            # Randomly decide if attack occurs
            if random.random() < attack_probability:
                results["attacks_attempted"] += 1
                
                # Pick random attack type
                attack_type = random.choice(list(AttackType))
                
                # Simulate attack success (very low probability with our security)
                success_prob = {
                    AttackType.DOUBLE_SPEND: 0.01,
                    AttackType.PROOF_FORGERY: 0.005,
                    AttackType.GRIEFING: 0.1,
                    AttackType.COLLUSION: 0.02,
                    AttackType.FLASH_LOAN: 0.001,
                    AttackType.MEV_EXTRACTION: 0.05
                }.get(attack_type, 0.01)
                
                if random.random() < success_prob:
                    results["attacks_successful"] += 1
                    loss = self.state.max_profit * random.uniform(0.5, 1.5)
                    results["total_losses"] += loss
                    
                    # Use insurance if available
                    if self.state.insurance_fund > loss:
                        results["insurance_used"] += loss
                else:
                    # Attack failed, attacker slashed
                    results["total_slashed"] += self.state.min_bond * self.state.slashing_ratio
        
        # Calculate statistics
        results["attack_success_rate"] = (
            results["attacks_successful"] / results["attacks_attempted"]
            if results["attacks_attempted"] > 0 else 0
        )
        results["avg_loss_per_attack"] = (
            results["total_losses"] / results["attacks_successful"]
            if results["attacks_successful"] > 0 else 0
        )
        results["net_security_profit"] = results["total_slashed"] - results["total_losses"]
        
        return results


class GriefingSimulation:
    """Simulate griefing attacks and defenses"""
    
    def __init__(self, protocol_state: ProtocolState):
        self.state = protocol_state
    
    def simulate_dos_attack(
        self,
        attacker_capital: float,
        attack_duration_blocks: int
    ) -> Dict:
        """Simulate DoS attack economics"""
        # Cost per failed transaction
        gas_cost = 0.001  # ETH
        
        # Maximum transactions per block
        max_txs_per_block = 100
        
        # Total attack cost
        total_cost = gas_cost * max_txs_per_block * attack_duration_blocks
        
        # Can attacker afford it?
        can_afford = attacker_capital >= total_cost
        
        # Impact on protocol
        blocked_operations = max_txs_per_block * attack_duration_blocks
        estimated_loss = blocked_operations * 0.01  # 0.01 ETH per blocked op
        
        return {
            "attack_cost": total_cost,
            "attacker_can_afford": can_afford,
            "blocked_operations": blocked_operations,
            "estimated_protocol_loss": estimated_loss,
            "attack_profitable": False,  # DoS is never profitable
            "defense_effective": not can_afford or total_cost > estimated_loss
        }
    
    def simulate_spam_attack(
        self,
        spam_rate: int,  # txs per block
        blocks: int
    ) -> Dict:
        """Simulate transaction spam attack"""
        # With rate limiting
        max_allowed = 3  # ops per block per user
        
        effective_spam = min(spam_rate, max_allowed)
        total_spam = effective_spam * blocks
        
        # Cost to attacker
        cost_per_tx = 0.001
        total_cost = spam_rate * blocks * cost_per_tx
        
        # Damage to protocol (minimal with rate limiting)
        damage = effective_spam * blocks * 0.0001
        
        return {
            "intended_spam": spam_rate * blocks,
            "effective_spam": total_spam,
            "blocked_by_rate_limit": (spam_rate - effective_spam) * blocks,
            "attacker_cost": total_cost,
            "protocol_damage": damage,
            "rate_limiting_effective": effective_spam < spam_rate
        }


def run_full_simulation():
    """Run complete game theory simulation"""
    print("=" * 60)
    print("PIL Protocol Game Theory Simulation")
    print("=" * 60)
    
    # Initialize protocol state
    state = ProtocolState(
        tvl=1000.0,  # 1000 ETH TVL
        insurance_fund=100.0,  # 100 ETH insurance
        total_operator_bonds=50.0,  # 50 ETH total bonds
        min_bond=1.0,
        slashing_ratio=0.5,
        attack_cost=0.1
    )
    
    sim = BridgeAttackSimulation(state)
    
    # Add actors
    for i in range(5):
        sim.add_actor(Actor(
            id=f"honest_{i}",
            actor_type=ActorType.HONEST_OPERATOR,
            capital=10.0,
            bond=1.0
        ))
    
    sim.add_actor(Actor(
        id="attacker_1",
        actor_type=ActorType.RATIONAL_ATTACKER,
        capital=100.0,
        bond=0.0
    ))
    
    # Test 1: Verify economic security
    print("\n1. Economic Security Verification")
    print("-" * 40)
    is_secure, explanation = sim.verify_economic_security()
    print(f"   Secure: {is_secure}")
    print(f"   {explanation}")
    
    # Test 2: Attack strategy analysis
    print("\n2. Attack Strategy Analysis")
    print("-" * 40)
    attacker = sim.actors[-1]
    for attack_type in AttackType:
        should_attack, expected_profit, reason = sim.simulate_attacker_strategy(
            attacker, attack_type
        )
        print(f"   {attack_type.value}:")
        print(f"      Should attack: {should_attack}")
        print(f"      {reason}")
    
    # Test 3: Minimum viable stake
    print("\n3. Minimum Viable Stake")
    print("-" * 40)
    min_stake = sim.calculate_minimum_viable_stake()
    print(f"   Minimum stake required: {min_stake:.4f} ETH")
    print(f"   Current min bond: {state.min_bond:.4f} ETH")
    print(f"   Adequate: {state.min_bond >= min_stake}")
    
    # Test 4: Insurance adequacy
    print("\n4. Insurance Fund Adequacy")
    print("-" * 40)
    is_adequate, coverage = sim.verify_insurance_adequacy()
    print(f"   Adequate: {is_adequate}")
    print(f"   Coverage ratio: {coverage:.2f}x")
    
    # Test 5: Monte Carlo simulation
    print("\n5. Monte Carlo Simulation (10,000 scenarios)")
    print("-" * 40)
    mc_results = sim.run_monte_carlo(scenarios=10000, attack_probability=0.1)
    print(f"   Attacks attempted: {mc_results['attacks_attempted']}")
    print(f"   Attacks successful: {mc_results['attacks_successful']}")
    print(f"   Success rate: {mc_results['attack_success_rate']:.2%}")
    print(f"   Total slashed: {mc_results['total_slashed']:.4f} ETH")
    print(f"   Total losses: {mc_results['total_losses']:.4f} ETH")
    print(f"   Net security profit: {mc_results['net_security_profit']:.4f} ETH")
    
    # Test 6: Griefing simulation
    print("\n6. Griefing Attack Simulation")
    print("-" * 40)
    grief_sim = GriefingSimulation(state)
    dos_result = grief_sim.simulate_dos_attack(
        attacker_capital=10.0,
        attack_duration_blocks=100
    )
    print(f"   DoS attack cost: {dos_result['attack_cost']:.4f} ETH")
    print(f"   Defense effective: {dos_result['defense_effective']}")
    
    spam_result = grief_sim.simulate_spam_attack(spam_rate=100, blocks=100)
    print(f"   Spam blocked by rate limit: {spam_result['blocked_by_rate_limit']:.0f}")
    print(f"   Rate limiting effective: {spam_result['rate_limiting_effective']}")
    
    print("\n" + "=" * 60)
    print("Simulation Complete")
    print("=" * 60)


if __name__ == "__main__":
    run_full_simulation()
