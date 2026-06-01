"""Surgery SDK — Surgical Shellcode Disassembly & Reassembly Toolkit.

Provides micro-level access to CobaltStrike beacon shellcode components
for UDRL developers, MalDev engineers, and security researchers.

Core classes:
    BeaconSurgeon   — High-level orchestrator for payload surgery
    PayloadMap      — Byte-accurate segment boundary mapping
    ConfigSurgeon   — Field-level config read/write/re-encrypt
    LoaderSurgeon   — Loader stub replacement and validation
    SleepMaskSurgeon — Sleep mask injection/swap/removal
    SurgeryValidator — Pre/post surgery structural validation

Usage:
    from cs_aggregator.surgery import BeaconSurgeon

    surgeon = BeaconSurgeon("beacon.bin")
    surgeon.config["SETTING_SLEEPTIME"] = 30000
    surgeon.replace_loader(open("my_udrl.bin", "rb").read())
    patched = surgeon.build()
"""

from cs_aggregator.surgery.builder import BeaconSurgeon
from cs_aggregator.surgery.payload_map import PayloadMap, SegmentInfo
from cs_aggregator.surgery.config_surgeon import ConfigSurgeon
from cs_aggregator.surgery.loader_surgeon import LoaderSurgeon
from cs_aggregator.surgery.sleepmask_surgeon import SleepMaskSurgeon
from cs_aggregator.surgery.validator import SurgeryValidator, ValidationResult
from cs_aggregator.surgery.component_ops import ComponentExtractor

__all__ = [
    "BeaconSurgeon",
    "PayloadMap",
    "SegmentInfo",
    "ConfigSurgeon",
    "LoaderSurgeon",
    "SleepMaskSurgeon",
    "SurgeryValidator",
    "ValidationResult",
    "ComponentExtractor",
]