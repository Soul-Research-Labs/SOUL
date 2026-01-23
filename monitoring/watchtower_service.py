"""
PIL Protocol - Watchtower Anomaly Detection Service
Deploys anomaly detection to watchtower nodes for real-time monitoring

Author: PIL Protocol Team
Date: January 2026
"""

import asyncio
import json
import logging
import signal
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Add models directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "models"))

from anomaly_detector import (
    TransactionAnomalyDetector,
    Transaction,
    AnomalyAlert,
    RiskLevel,
    AnomalyType
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('watchtower.log')
    ]
)
logger = logging.getLogger('watchtower')


@dataclass
class WatchtowerConfig:
    """Configuration for watchtower node"""
    node_id: str
    rpc_endpoints: List[str]
    chains: List[int]
    alert_webhook_url: Optional[str]
    circuit_breaker_address: str
    poll_interval: int = 12  # seconds (1 block)
    batch_size: int = 100
    confidence_threshold: float = 0.7
    auto_escalate: bool = True
    auto_escalate_threshold: float = 0.9
    redis_url: Optional[str] = None
    prometheus_port: int = 9090


@dataclass
class ChainState:
    """State tracking for a chain"""
    chain_id: int
    last_block: int
    pending_alerts: List[AnomalyAlert]
    is_healthy: bool = True
    last_error: Optional[str] = None


class AlertPipeline:
    """Alert routing and escalation pipeline"""
    
    def __init__(self, config: WatchtowerConfig):
        self.config = config
        self.alert_queue: asyncio.Queue = asyncio.Queue()
        self.sent_alerts: Dict[str, datetime] = {}
        self.alert_cooldown = 60  # seconds
    
    async def enqueue(self, alert: AnomalyAlert):
        """Add alert to processing queue"""
        # Deduplicate by alert_id
        if alert.alert_id in self.sent_alerts:
            cooldown_end = self.sent_alerts[alert.alert_id]
            if (datetime.now() - cooldown_end).seconds < self.alert_cooldown:
                return
        
        await self.alert_queue.put(alert)
    
    async def process_alerts(self):
        """Process alerts from queue"""
        while True:
            try:
                alert = await asyncio.wait_for(
                    self.alert_queue.get(),
                    timeout=1.0
                )
                await self._route_alert(alert)
                self.sent_alerts[alert.alert_id] = datetime.now()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Alert processing error: {e}")
    
    async def _route_alert(self, alert: AnomalyAlert):
        """Route alert to appropriate handlers"""
        logger.warning(f"ALERT [{alert.risk_level.name}]: {alert.anomaly_type.name} - {alert.description}")
        
        # Critical alerts trigger circuit breaker
        if alert.risk_level == RiskLevel.CRITICAL and self.config.auto_escalate:
            await self._trigger_circuit_breaker(alert)
        
        # Send webhook notification
        if self.config.alert_webhook_url:
            await self._send_webhook(alert)
        
        # Log to file
        self._log_alert(alert)
    
    async def _trigger_circuit_breaker(self, alert: AnomalyAlert):
        """Trigger on-chain circuit breaker"""
        logger.critical(f"TRIGGERING CIRCUIT BREAKER for {alert.anomaly_type.name}")
        
        # In production, this would call the circuit breaker contract
        # For now, log the action
        trigger_data = {
            "action": "trigger_circuit_breaker",
            "alert_id": alert.alert_id,
            "anomaly_type": alert.anomaly_type.name,
            "confidence": alert.confidence,
            "timestamp": datetime.now().isoformat()
        }
        logger.critical(f"Circuit breaker trigger: {json.dumps(trigger_data)}")
    
    async def _send_webhook(self, alert: AnomalyAlert):
        """Send alert to webhook endpoint"""
        try:
            import aiohttp
            
            payload = {
                "alert_id": alert.alert_id,
                "type": alert.anomaly_type.name,
                "risk_level": alert.risk_level.name,
                "confidence": alert.confidence,
                "description": alert.description,
                "transactions": alert.transactions,
                "timestamp": alert.timestamp,
                "metadata": alert.metadata
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.alert_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        logger.error(f"Webhook failed: {response.status}")
        except ImportError:
            logger.warning("aiohttp not installed, skipping webhook")
        except Exception as e:
            logger.error(f"Webhook error: {e}")
    
    def _log_alert(self, alert: AnomalyAlert):
        """Log alert to file"""
        alert_log = Path("alerts.jsonl")
        with open(alert_log, "a") as f:
            log_entry = {
                "alert_id": alert.alert_id,
                "type": alert.anomaly_type.name,
                "risk_level": alert.risk_level.name,
                "confidence": alert.confidence,
                "description": alert.description,
                "transactions": alert.transactions,
                "timestamp": alert.timestamp,
                "logged_at": datetime.now().isoformat()
            }
            f.write(json.dumps(log_entry) + "\n")


class BlockchainMonitor:
    """Monitor blockchain for new transactions"""
    
    def __init__(self, chain_id: int, rpc_url: str):
        self.chain_id = chain_id
        self.rpc_url = rpc_url
        self.last_block = 0
    
    async def get_latest_block(self) -> int:
        """Get latest block number"""
        try:
            import aiohttp
            
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.rpc_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    data = await response.json()
                    return int(data["result"], 16)
        except ImportError:
            # Fallback for testing without aiohttp
            return self.last_block + 1
        except Exception as e:
            logger.error(f"Failed to get block number: {e}")
            return self.last_block
    
    async def get_block_transactions(self, block_number: int) -> List[Dict]:
        """Get transactions from a block"""
        try:
            import aiohttp
            
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [hex(block_number), True],
                "id": 1
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.rpc_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    data = await response.json()
                    if data.get("result"):
                        return data["result"].get("transactions", [])
                    return []
        except ImportError:
            return []
        except Exception as e:
            logger.error(f"Failed to get block transactions: {e}")
            return []
    
    def parse_transaction(self, tx_data: Dict, block_timestamp: int) -> Transaction:
        """Parse raw transaction data into Transaction object"""
        return Transaction(
            tx_hash=tx_data.get("hash", ""),
            sender=tx_data.get("from", ""),
            recipient=tx_data.get("to", "") or "",
            value=int(tx_data.get("value", "0x0"), 16) / 1e18,
            gas_used=int(tx_data.get("gas", "0x0"), 16),
            gas_price=int(tx_data.get("gasPrice", "0x0"), 16) / 1e9,
            block_number=int(tx_data.get("blockNumber", "0x0"), 16),
            timestamp=block_timestamp,
            method_id=tx_data.get("input", "0x")[:10],
            is_bridge=self._is_bridge_tx(tx_data),
            source_chain=self.chain_id,
            dest_chain=self._extract_dest_chain(tx_data),
            proof_hash=self._extract_proof_hash(tx_data)
        )
    
    def _is_bridge_tx(self, tx_data: Dict) -> bool:
        """Check if transaction is a bridge operation"""
        input_data = tx_data.get("input", "")
        bridge_selectors = [
            "0x12345678",  # bridgeProof
            "0x9876abcd",  # relayProof
            "0xabcd1234",  # claimProof
        ]
        return input_data[:10] in bridge_selectors
    
    def _extract_dest_chain(self, tx_data: Dict) -> int:
        """Extract destination chain from bridge tx"""
        # Simplified - in production would decode calldata
        return self.chain_id
    
    def _extract_proof_hash(self, tx_data: Dict) -> Optional[str]:
        """Extract proof hash from bridge tx"""
        input_data = tx_data.get("input", "")
        if len(input_data) >= 74:
            return "0x" + input_data[10:74]
        return None


class MetricsCollector:
    """Prometheus metrics collector"""
    
    def __init__(self, port: int):
        self.port = port
        self.metrics = {
            "transactions_processed": 0,
            "alerts_generated": 0,
            "critical_alerts": 0,
            "blocks_processed": 0,
            "detection_latency_ms": [],
            "chain_health": {}
        }
    
    def increment(self, metric: str, value: int = 1):
        """Increment a counter metric"""
        if metric in self.metrics:
            if isinstance(self.metrics[metric], int):
                self.metrics[metric] += value
    
    def record_latency(self, latency_ms: float):
        """Record detection latency"""
        self.metrics["detection_latency_ms"].append(latency_ms)
        # Keep only last 1000 samples
        if len(self.metrics["detection_latency_ms"]) > 1000:
            self.metrics["detection_latency_ms"] = self.metrics["detection_latency_ms"][-1000:]
    
    def set_chain_health(self, chain_id: int, healthy: bool):
        """Set chain health status"""
        self.metrics["chain_health"][chain_id] = healthy
    
    def get_prometheus_metrics(self) -> str:
        """Generate Prometheus-compatible metrics output"""
        lines = [
            f"# HELP watchtower_transactions_processed Total transactions processed",
            f"# TYPE watchtower_transactions_processed counter",
            f"watchtower_transactions_processed {self.metrics['transactions_processed']}",
            f"",
            f"# HELP watchtower_alerts_generated Total alerts generated",
            f"# TYPE watchtower_alerts_generated counter",
            f"watchtower_alerts_generated {self.metrics['alerts_generated']}",
            f"",
            f"# HELP watchtower_critical_alerts Total critical alerts",
            f"# TYPE watchtower_critical_alerts counter",
            f"watchtower_critical_alerts {self.metrics['critical_alerts']}",
            f"",
            f"# HELP watchtower_blocks_processed Total blocks processed",
            f"# TYPE watchtower_blocks_processed counter",
            f"watchtower_blocks_processed {self.metrics['blocks_processed']}",
        ]
        
        if self.metrics["detection_latency_ms"]:
            avg_latency = sum(self.metrics["detection_latency_ms"]) / len(self.metrics["detection_latency_ms"])
            lines.extend([
                f"",
                f"# HELP watchtower_detection_latency_ms Average detection latency",
                f"# TYPE watchtower_detection_latency_ms gauge",
                f"watchtower_detection_latency_ms {avg_latency:.2f}",
            ])
        
        for chain_id, healthy in self.metrics["chain_health"].items():
            lines.extend([
                f"",
                f"# HELP watchtower_chain_health Chain health status",
                f"# TYPE watchtower_chain_health gauge",
                f'watchtower_chain_health{{chain_id="{chain_id}"}} {1 if healthy else 0}',
            ])
        
        return "\n".join(lines)
    
    async def start_server(self):
        """Start metrics HTTP server"""
        try:
            from aiohttp import web
            
            async def metrics_handler(request):
                return web.Response(
                    text=self.get_prometheus_metrics(),
                    content_type="text/plain"
                )
            
            app = web.Application()
            app.router.add_get("/metrics", metrics_handler)
            
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "0.0.0.0", self.port)
            await site.start()
            
            logger.info(f"Metrics server started on port {self.port}")
        except ImportError:
            logger.warning("aiohttp not installed, metrics server disabled")
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")


class WatchtowerService:
    """Main watchtower service orchestrating anomaly detection"""
    
    def __init__(self, config: WatchtowerConfig):
        self.config = config
        self.detector = TransactionAnomalyDetector({
            "confidence_threshold": config.confidence_threshold,
            "window_size": 1000
        })
        self.alert_pipeline = AlertPipeline(config)
        self.metrics = MetricsCollector(config.prometheus_port)
        self.monitors: Dict[int, BlockchainMonitor] = {}
        self.chain_states: Dict[int, ChainState] = {}
        self.running = False
        
        # Initialize monitors for each chain
        for i, chain_id in enumerate(config.chains):
            rpc_url = config.rpc_endpoints[i % len(config.rpc_endpoints)]
            self.monitors[chain_id] = BlockchainMonitor(chain_id, rpc_url)
            self.chain_states[chain_id] = ChainState(
                chain_id=chain_id,
                last_block=0,
                pending_alerts=[]
            )
    
    async def start(self):
        """Start the watchtower service"""
        logger.info(f"Starting Watchtower Node {self.config.node_id}")
        logger.info(f"Monitoring chains: {self.config.chains}")
        
        self.running = True
        
        # Start all tasks
        tasks = [
            asyncio.create_task(self.alert_pipeline.process_alerts()),
            asyncio.create_task(self.metrics.start_server()),
        ]
        
        for chain_id in self.config.chains:
            tasks.append(asyncio.create_task(self._monitor_chain(chain_id)))
        
        # Handle graceful shutdown
        def shutdown_handler(sig, frame):
            logger.info("Shutting down watchtower...")
            self.running = False
        
        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Watchtower tasks cancelled")
    
    async def _monitor_chain(self, chain_id: int):
        """Monitor a single chain for new blocks"""
        monitor = self.monitors[chain_id]
        state = self.chain_states[chain_id]
        
        logger.info(f"Starting monitor for chain {chain_id}")
        
        while self.running:
            try:
                latest_block = await monitor.get_latest_block()
                
                if latest_block > state.last_block:
                    # Process new blocks
                    start_block = state.last_block + 1 if state.last_block > 0 else latest_block
                    
                    for block_num in range(start_block, latest_block + 1):
                        await self._process_block(chain_id, block_num)
                    
                    state.last_block = latest_block
                    state.is_healthy = True
                    self.metrics.set_chain_health(chain_id, True)
                
                await asyncio.sleep(self.config.poll_interval)
                
            except Exception as e:
                logger.error(f"Chain {chain_id} monitor error: {e}")
                state.is_healthy = False
                state.last_error = str(e)
                self.metrics.set_chain_health(chain_id, False)
                await asyncio.sleep(self.config.poll_interval * 2)
    
    async def _process_block(self, chain_id: int, block_number: int):
        """Process all transactions in a block"""
        monitor = self.monitors[chain_id]
        
        transactions = await monitor.get_block_transactions(block_number)
        logger.debug(f"Chain {chain_id} block {block_number}: {len(transactions)} txs")
        
        self.metrics.increment("blocks_processed")
        
        block_timestamp = int(datetime.now().timestamp())
        
        for tx_data in transactions:
            try:
                start_time = datetime.now()
                
                tx = monitor.parse_transaction(tx_data, block_timestamp)
                alerts = self.detector.process_transaction(tx)
                
                latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                self.metrics.record_latency(latency_ms)
                self.metrics.increment("transactions_processed")
                
                for alert in alerts:
                    self.metrics.increment("alerts_generated")
                    if alert.risk_level == RiskLevel.CRITICAL:
                        self.metrics.increment("critical_alerts")
                    await self.alert_pipeline.enqueue(alert)
                    
            except Exception as e:
                logger.error(f"Transaction processing error: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current watchtower status"""
        return {
            "node_id": self.config.node_id,
            "running": self.running,
            "chains": {
                chain_id: {
                    "last_block": state.last_block,
                    "is_healthy": state.is_healthy,
                    "pending_alerts": len(state.pending_alerts),
                    "last_error": state.last_error
                }
                for chain_id, state in self.chain_states.items()
            },
            "metrics": {
                "transactions_processed": self.metrics.metrics["transactions_processed"],
                "alerts_generated": self.metrics.metrics["alerts_generated"],
                "critical_alerts": self.metrics.metrics["critical_alerts"]
            },
            "detector_stats": {
                "addresses_tracked": len(self.detector.address_profiles),
                "total_alerts": len(self.detector.alerts)
            }
        }


def load_config(config_path: Optional[str] = None) -> WatchtowerConfig:
    """Load configuration from file or environment"""
    import os
    
    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            data = json.load(f)
            return WatchtowerConfig(**data)
    
    # Load from environment
    return WatchtowerConfig(
        node_id=os.getenv("WATCHTOWER_NODE_ID", "watchtower-1"),
        rpc_endpoints=os.getenv("RPC_ENDPOINTS", "http://localhost:8545").split(","),
        chains=[int(c) for c in os.getenv("CHAINS", "1,42161,10").split(",")],
        alert_webhook_url=os.getenv("ALERT_WEBHOOK_URL"),
        circuit_breaker_address=os.getenv("CIRCUIT_BREAKER_ADDRESS", "0x0"),
        poll_interval=int(os.getenv("POLL_INTERVAL", "12")),
        confidence_threshold=float(os.getenv("CONFIDENCE_THRESHOLD", "0.7")),
        auto_escalate=os.getenv("AUTO_ESCALATE", "true").lower() == "true",
        auto_escalate_threshold=float(os.getenv("AUTO_ESCALATE_THRESHOLD", "0.9")),
        prometheus_port=int(os.getenv("PROMETHEUS_PORT", "9090"))
    )


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PIL Watchtower Anomaly Detection Service")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--node-id", help="Node identifier")
    parser.add_argument("--rpc", help="Comma-separated RPC endpoints")
    parser.add_argument("--chains", help="Comma-separated chain IDs")
    args = parser.parse_args()
    
    config = load_config(args.config)
    
    if args.node_id:
        config.node_id = args.node_id
    if args.rpc:
        config.rpc_endpoints = args.rpc.split(",")
    if args.chains:
        config.chains = [int(c) for c in args.chains.split(",")]
    
    service = WatchtowerService(config)
    await service.start()


if __name__ == "__main__":
    asyncio.run(main())
