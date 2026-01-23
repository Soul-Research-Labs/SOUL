# PIL Watchtower Anomaly Detection - Deployment Guide

## Overview

The PIL Watchtower system deploys anomaly detection to monitor cross-chain operations in real-time. It consists of:

- **Watchtower Service**: Python-based anomaly detection with ML capabilities
- **Redis**: State sharing and alert deduplication
- **Prometheus**: Metrics collection
- **Grafana**: Visualization dashboards
- **AlertManager**: Alert routing and escalation

## Quick Start

### 1. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit with your settings
nano .env
```

Required environment variables:
```bash
# RPC Endpoints (comma-separated)
RPC_ENDPOINTS=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY,https://arb-mainnet.g.alchemy.com/v2/YOUR_KEY

# Alert webhook (Slack, Discord, or custom)
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/xxx

# Circuit breaker contract address
CIRCUIT_BREAKER_ADDRESS=0x...

# Grafana password
GRAFANA_PASSWORD=your-secure-password

# Optional: PagerDuty for critical alerts
PAGERDUTY_SERVICE_KEY=your-key
```

### 2. Start the Stack

```bash
# Navigate to monitoring directory
cd monitoring

# Start all services
docker-compose -f docker-compose.watchtower.yml up -d

# Check status
docker-compose -f docker-compose.watchtower.yml ps
```

### 3. Verify Deployment

```bash
# Check watchtower logs
docker logs pil-watchtower-1 -f

# Check metrics endpoint
curl http://localhost:9090/metrics

# Check Prometheus targets
open http://localhost:9092/targets

# Access Grafana
open http://localhost:3001
# Default login: admin / ${GRAFANA_PASSWORD}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Blockchain Networks                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Ethereum │  │ Arbitrum │  │ Optimism │  │   Base   │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
└───────┼─────────────┼─────────────┼─────────────┼──────────┘
        │             │             │             │
        └─────────────┼─────────────┼─────────────┘
                      │             │
                      ▼             ▼
            ┌─────────────────────────────────┐
            │     Watchtower Nodes (2+)       │
            │  ┌─────────────────────────┐    │
            │  │  Anomaly Detector (ML)  │    │
            │  │  - Statistical Analysis │    │
            │  │  - Pattern Detection    │    │
            │  │  - Bridge Monitoring    │    │
            │  └───────────┬─────────────┘    │
            └──────────────┼──────────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌───────────┐
        │  Redis  │  │Prometheus│  │AlertManager│
        └─────────┘  └────┬────┘  └─────┬─────┘
                          │             │
                          ▼             ▼
                    ┌─────────┐   ┌──────────┐
                    │ Grafana │   │  Slack/  │
                    │Dashboard│   │ PagerDuty│
                    └─────────┘   └──────────┘
```

## Configuration

### Watchtower Config (watchtower.config.json)

```json
{
  "node_id": "watchtower-1",
  "chains": [1, 42161, 10, 8453],
  "confidence_threshold": 0.7,
  "auto_escalate": true,
  "auto_escalate_threshold": 0.9,
  "detection_config": {
    "flash_loan_detection": true,
    "sandwich_detection": true,
    "sybil_detection": true
  }
}
```

### Detection Thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| `confidence_threshold` | 0.7 | Minimum confidence to generate alert |
| `auto_escalate_threshold` | 0.9 | Confidence level to auto-trigger circuit breaker |
| `z_score_threshold` | 3.0 | Z-score for statistical anomaly detection |

### Escalation Rules

1. **CRITICAL** (confidence ≥ 0.9): Auto-trigger circuit breaker
2. **HIGH** (confidence ≥ 0.7): Alert security team
3. **MEDIUM** (confidence ≥ 0.5): Log and monitor
4. **LOW** (confidence < 0.5): Log only

## Monitoring

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `watchtower_transactions_processed` | Counter | Total transactions analyzed |
| `watchtower_alerts_generated` | Counter | Total alerts created |
| `watchtower_critical_alerts` | Counter | Critical severity alerts |
| `watchtower_blocks_processed` | Counter | Blocks processed |
| `watchtower_detection_latency_ms` | Gauge | Average detection latency |
| `watchtower_chain_health` | Gauge | Chain connection health |

### Grafana Dashboards

Import the pre-built dashboards:
1. Watchtower Overview
2. Anomaly Detection Metrics
3. Alert History
4. Chain Health

### Log Files

- `/var/log/watchtower/watchtower.log` - Main service logs
- `/var/log/watchtower/alerts.jsonl` - Alert history (JSON Lines format)

## Alert Types

| Type | Description | Risk Level |
|------|-------------|------------|
| `BRIDGE_EXPLOIT` | Double-spend or value mismatch | CRITICAL |
| `FLASH_LOAN_PATTERN` | Same-block arbitrage pattern | HIGH |
| `SANDWICH_ATTACK` | MEV sandwich detected | HIGH |
| `UNUSUAL_VOLUME` | Statistical volume anomaly | MEDIUM |
| `TIMING_ANOMALY` | Unusual transaction timing | MEDIUM |
| `WASH_TRADING` | Bidirectional trading pattern | MEDIUM |
| `SYBIL_ATTACK` | New address high activity | MEDIUM |

## Scaling

### Horizontal Scaling

Add more watchtower nodes:

```yaml
# docker-compose.watchtower.yml
watchtower-3:
  extends: watchtower-1
  environment:
    - WATCHTOWER_NODE_ID=watchtower-3
    - PROMETHEUS_PORT=9092
  ports:
    - "9092:9092"
```

### Chain Assignment

For large deployments, assign specific chains to specific nodes:

```bash
# Node 1: Ethereum + Arbitrum
CHAINS=1,42161

# Node 2: Optimism + Base
CHAINS=10,8453

# Node 3: zkSync + Scroll + Linea
CHAINS=324,534352,59144
```

## Troubleshooting

### Common Issues

1. **RPC Connection Failures**
   ```bash
   # Check RPC connectivity
   curl -X POST -H "Content-Type: application/json" \
     --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
     $RPC_ENDPOINT
   ```

2. **High Memory Usage**
   - Reduce `window_size` in config
   - Increase container memory limits

3. **Alert Flooding**
   - Increase `confidence_threshold`
   - Adjust `alert_cooldown` in alert pipeline

### Health Checks

```bash
# Check all services
docker-compose -f docker-compose.watchtower.yml ps

# Check specific watchtower health
curl http://localhost:9090/metrics | grep chain_health

# Check Redis
docker exec pil-redis redis-cli ping

# Check Prometheus targets
curl http://localhost:9092/api/v1/targets
```

## Security Considerations

1. **RPC Endpoints**: Use authenticated endpoints with rate limiting
2. **Webhook URLs**: Keep alert webhooks secret
3. **Network**: Run on private network, expose only necessary ports
4. **Secrets**: Use Docker secrets or external secret management

## Integration with Circuit Breaker

When a critical alert is triggered, the watchtower can automatically call the circuit breaker:

```python
async def _trigger_circuit_breaker(self, alert):
    # Calls BridgeCircuitBreaker.triggerCircuitBreaker()
    # with the anomaly details
    pass
```

Configure the circuit breaker address in the environment.

## Support

- Documentation: `docs/SECURITY_NEXT_STEPS.md`
- Issues: GitHub Issues
- Security: security@pil.network
