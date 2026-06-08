# Performance Benchmarks

| Detector | Latency (p99) | Throughput |
|----------|---------------|------------|
| Injection | 12us | 500K events/s |
| Lateral Movement | 8us | 800K events/s |
| C2 Beacon | 45us | 100K events/s |
| Exfiltration | 5us | 1M events/s |

## System Overhead

| Component | CPU | Memory |
|-----------|-----|--------|
| Syscall Monitor | 1.2% | 32MB |
| Network Monitor | 0.8% | 64MB |
| Memory Scanner | 0.5% | 16MB |
| Pipeline | 0.3% | 128MB |
| Total | 2.8% | 240MB |
