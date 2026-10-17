"""MITRE ATT&CK lookup table for Sandtrap findings (offline, static)."""

from __future__ import annotations

from .types import AttackRef

NAMES: dict[str, str] = {
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1552.001": "Credentials In Files",
    "T1552.004": "Private Keys",
    "T1071.001": "Web Protocols",
    "T1059.004": "Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1546.004": "Unix Shell Configuration Modification",
    "T1053.003": "Cron",
    "T1098.004": "SSH Authorized Keys",
    "T1070.004": "File Deletion",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1497.003": "Time Based Evasion",
    "T1082": "System Information Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1119": "Automated Collection",
}

# finding kind -> technique ids
KIND_ATTACK: dict[str, list[str]] = {
    "exfil": ["T1041"],
    "cred_file": ["T1552.001"],
    "cred_ssh": ["T1552.004"],
    "c2": ["T1071.001"],
    "persist": ["T1546.004"],
    "persist_cron": ["T1053.003"],
    "persist_ssh": ["T1098.004"],
    "dropper": ["T1105", "T1059.004"],
    "exec": ["T1059.004"],
    "self_delete": ["T1070.004"],
    "time_bomb": ["T1497.003"],
    "evasion": ["T1497"],
}


def attack_ref(technique_id: str) -> AttackRef:
    """Build an AttackRef (name + attack.mitre.org url) for a technique id."""
    tid = technique_id.strip().upper()
    return AttackRef(
        id=tid,
        name=NAMES.get(tid, "Unknown technique"),
        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    )
