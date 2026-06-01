"""Behavioral Sub-Engine — TTP and behavioral IOC extraction."""

from typing import Any, Dict, List, Optional


class BehavioralEngine:
    """Extract behavioral IOCs: syscalls, injection, spawn-to, sleep, evasion."""

    def extract(
        self,
        config: Dict[str, Any],
        raw_data: Optional[bytes] = None,
        pe_info: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Extract all behavioral IOCs."""
        result: Dict[str, Any] = {
            "processes": [],
            "syscall": {},
            "injection": {},
            "sleep_profile": {},
            "evasion": {},
        }

        # Spawn-to targets
        for key in ("SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64", "SETTING_SPAWNTO"):
            val = config.get(key, "")
            if val and not all(c == "0" for c in str(val)):
                result["processes"].append(str(val))

        # Syscall method
        syscall = config.get("SETTING_SYSCALL_METHOD", 0)
        syscall_map = {0: "none", 1: "direct", 2: "indirect"}
        result["syscall"] = {
            "method": syscall_map.get(int(syscall), f"unknown({syscall})"),
            "raw_value": int(syscall),
        }

        # Process injection allocator
        allocator = config.get("SETTING_PROCINJ_ALLOCATOR", 0)
        alloc_map = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
        min_alloc = config.get("SETTING_PROCINJ_MINALLOC", 0)
        result["injection"] = {
            "allocator": alloc_map.get(int(allocator), f"unknown({allocator})"),
            "min_alloc": int(min_alloc) if min_alloc else 0,
            "bof_reuse_memory": bool(config.get("SETTING_PROCINJ_BOF_REUSE_MEM", 0)),
        }

        # Sleep profile
        sleep_ms = config.get("SETTING_SLEEPTIME", 0)
        jitter = config.get("SETTING_JITTER", 0)
        gargle = config.get("SETTING_GARGLE_NOOK", 0)
        result["sleep_profile"] = {
            "sleep_ms": int(sleep_ms) if sleep_ms else 0,
            "jitter_pct": int(jitter) if jitter else 0,
            "sleep_mask_enabled": bool(gargle),
        }

        # Evasion features
        cleanup = config.get("SETTING_CLEANUP", 0)
        exit_funk = config.get("SETTING_EXIT_FUNK", 0)
        exit_map = {0: "none", 1: "ExitProcess", 2: "ExitThread"}

        # BeaconGate detection
        beacon_gate = config.get("SETTING_BEACON_GATE", 0)
        drip_loading = config.get("SETTING_RDLL_USE_DRIPLOADING", 0)

        result["evasion"] = {
            "cleanup": bool(cleanup),
            "exit_function": exit_map.get(int(exit_funk), f"unknown({exit_funk})"),
            "beacon_gate_enabled": bool(beacon_gate),
            "drip_loading_enabled": bool(drip_loading),
        }

        if drip_loading:
            result["evasion"]["drip_delay_ms"] = int(
                config.get("SETTING_RDLL_DRIPLOAD_DELAY", 0)
            )

        result["processes"] = list(set(result["processes"]))
        return result
