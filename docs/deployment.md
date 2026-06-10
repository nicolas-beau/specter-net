# Deployment Guide

## Quick Start
```bash
git clone https://github.com/nicolas-beau/specter-net.git
cd specter-net
pip install -r requirements.txt
python -m specter_net.main
```

## Docker
```bash
docker build -t specter-net .
docker run --net=host --cap-add=NET_ADMIN specter-net
```

## Integration
- Phantom-Veil: auto-quarantine on threat detection
- Cerebro: ML telemetry pipeline
- Obsidian-Core: central policy orchestration
