"""Main entry point for specter-net."""
import argparse, logging, signal, sys
from .config import Config
from .pipeline import EventPipeline
from .monitors import SyscallMonitor, NetworkMonitor, MemoryMonitor
from .detectors import InjectionDetector, LateralMovementDetector, C2Detector, ExfiltrationDetector
from .outputs import PhantomVeilOutput, CerebroOutput

def main():
    parser = argparse.ArgumentParser(description="Specter-Net Threat Detection")
    parser.add_argument("--config", default="config/specter-net.yaml")
    args = parser.parse_args()
    config = Config(args.config)
    config.load()
    pipeline = EventPipeline()
    pipeline.add_detector(InjectionDetector().detect)
    pipeline.add_detector(LateralMovementDetector().detect)
    pipeline.add_detector(C2Detector().detect)
    pipeline.add_detector(ExfiltrationDetector().detect)
    pv = PhantomVeilOutput()
    pipeline.add_output(pv.send)
    pipeline.start()
    logging.info("Specter-Net running")
    signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))
    signal.pause()
if __name__ == "__main__": main()
