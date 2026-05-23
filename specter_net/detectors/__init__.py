"""Threat detectors for specter-net."""
from .injection import InjectionDetector
from .lateral_movement import LateralMovementDetector
from .c2_detector import C2Detector
from .exfiltration import ExfiltrationDetector
