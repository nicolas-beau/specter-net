# eBPF Programs

Kernel-level tracing for specter-net.

## Build
```bash
clang -O2 -target bpf -c syscall_trace.c -o syscall_trace.o
```
