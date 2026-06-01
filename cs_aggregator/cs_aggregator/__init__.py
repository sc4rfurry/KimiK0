"""
cs_aggregator — CobaltStrike Beacon Shellcode Aggregation & Dissection Engine.

A from-scratch, version-adaptive Python engine for parsing CobaltStrike
beacon shellcode payloads across CS versions 4.9.1 through 4.12+.

Features:
    - Multi-stage pipeline with integrated plugin system
    - Surgery SDK for micro-level shellcode disassembly & reassembly
    - BUD (Beacon User Data) structure analyzer (v1/v2/v3)
    - IOC Central Engine with 5 sub-engines + STIX/MISP/CSV export
    - Capstone-powered instruction-level shellcode analysis
    - Dynamic YARA rule generation from extracted artifacts
    - CS 4.11/4.12 support: drip-loading, BeaconGate, UDC2, novel sleepmask
"""

__version__ = "5.2.0"
__author__ = "y4kuz4"
__description__ = "CobaltStrike Beacon Shellcode Aggregation & Dissection Engine"

