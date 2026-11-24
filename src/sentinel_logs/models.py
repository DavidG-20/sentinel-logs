"""Typed data models for SIEM rules, security alerts, and analysis reports."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SignatureRule:
    """Single regex-based detection rule loaded from YAML."""

    rule_id: str
    name: str
    severity: str  # HIGH | MEDIUM | LOW
    category: str
    pattern: str


@dataclass(frozen=True)
class SecurityAlert:
    """Single security alert emitted by the Mini-SIEM engine."""

    rule_id: str
    title: str
    severity: str
    category: str
    source_ip: str
    subnet_24: str
    count: int
    detail: str
    sample_line: str = ""


@dataclass
class AnalysisReport:
    """Complete Mini-SIEM analysis summary."""

    total_lines: int
    unique_ips: int
    high_count: int
    medium_count: int
    low_count: int
    top_ips: dict[str, int] = field(default_factory=dict)
    top_subnets_24: dict[str, int] = field(default_factory=dict)
    alerts: list[SecurityAlert] = field(default_factory=list)
