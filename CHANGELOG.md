# Changelog

## [0.1.0-alpha] - 2026-06-06

### Added
- Core event system (TelemetryEvent, ThreatEvent)
- Syscall monitoring with eBPF/kprobe interface
- Network monitoring with flow analysis
- Memory forensics (RWX detection, rootkit indicators)
- Event pipeline with correlation
- Process injection detector (5 techniques)
- Lateral movement detector (SMB, PSRemoting, WMI, RDP, SSH)
- C2 beacon detector (timing analysis)
- Data exfiltration detector (volume + timing)
- Phantom-veil output connector
- Cerebro ML output connector
- Webhook alerting output
- Configuration system (YAML)
- Test suite
