# Specter-Net API Reference

## Monitors

### SyscallMonitor
```python
from specter_net.monitors import SyscallMonitor
monitor = SyscallMonitor(callback=my_callback)
monitor.start()
monitor.on_syscall(SyscallEvent(pid=1234, process_name="app", syscall="mprotect", args=["RWX"], ...))
```

### NetworkMonitor
```python
from specter_net.monitors import NetworkMonitor
monitor = NetworkMonitor(callback=my_callback)
monitor.on_flow(NetworkFlow(src_ip="10.0.0.1", dst_ip="8.8.8.8", ...))
monitor.on_dns_query(DNSQuery(query="evil.com", qtype="A", ...))
```

## Detectors

### InjectionDetector
Detects: process hollowing, DLL injection, reflective loading, thread hijack, APC injection

### LateralMovementDetector
Detects: SMB traversal, PSRemoting, WMI execution, RDP hopping, SSH lateral

### C2Detector
Detects: beacon patterns via timing analysis (jitter < threshold)

### ExfiltrationDetector
Detects: large transfers, volume anomalies, hourly thresholds

## Pipeline

```python
pipeline = EventPipeline()
pipeline.add_detector(InjectionDetector().detect)
pipeline.add_detector(C2Detector().detect)
pipeline.add_output(PhantomVeilOutput().send)
pipeline.start()
pipeline.ingest(telemetry_event)
```
