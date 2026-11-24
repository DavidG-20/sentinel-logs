"""Mini-SIEM log analysis engine: YAML signatures, SSH brute-force, /24 correlation, and spike detection."""

from collections import Counter, defaultdict
import csv
import io
import ipaddress
from pathlib import Path
import re
import statistics
from typing import Any

import yaml

from sentinel_logs.models import AnalysisReport, SecurityAlert, SignatureRule

DEFAULT_RULES_PATH = Path(__file__).parent / "rules" / "default_rules.yaml"

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
SSH_FAIL_RE = re.compile(
    r"(?:Failed password|Invalid user).*?\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)


def _valid_ipv4(raw_ip: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(raw_ip))
    except ValueError:
        return None


def _to_subnet_24(ip_str: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"{ip_str}/24", strict=False))
    except ValueError:
        return "unknown"


class RuleLoadError(ValueError):
    """Raised when a YAML rules file cannot be parsed or contains invalid regex."""


def load_rules(rules_path: Path | None = None) -> tuple[list[SignatureRule], dict[str, int]]:
    """Safely load signature rules and thresholds from a YAML file."""
    path = rules_path or DEFAULT_RULES_PATH
    try:
        data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise RuleLoadError("El archivo YAML debe contener un diccionario raíz.")
        thresholds = {
            "ssh_bruteforce_attempts": int(data.get("thresholds", {}).get("ssh_bruteforce_attempts", 5)),
            "subnet_coordinated_ips": int(data.get("thresholds", {}).get("subnet_coordinated_ips", 2)),
            "spike_min_requests": int(data.get("thresholds", {}).get("spike_min_requests", 12)),
        }
        rules = []
        for item in data.get("signature_rules", []):
            pattern_str = str(item["pattern"])
            re.compile(pattern_str)
            rules.append(
                SignatureRule(
                    rule_id=str(item["id"]),
                    name=str(item["name"]),
                    severity=str(item["severity"]).upper(),
                    category=str(item["category"]),
                    pattern=pattern_str,
                )
            )
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError, re.error) as exc:
        raise RuleLoadError(f"Archivo de reglas YAML inválido ({path}): {exc}") from exc
    return rules, thresholds


def analyze_log_text(
    log_text: str,
    rules_path: Path | None = None,
) -> AnalysisReport:
    """Analyze raw SSH or Nginx/Apache log text and emit correlated security alerts."""
    rules, thresholds = load_rules(rules_path)
    compiled_rules = [(rule, re.compile(rule.pattern)) for rule in rules]

    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    ip_activity: Counter[str] = Counter()
    ssh_failures: Counter[str] = Counter()
    ssh_samples: dict[str, str] = {}

    # Track signature hits grouped by (rule_id, source_ip)
    sig_hits: dict[tuple[str, str], dict[str, Any]] = {}
    attacking_ips_by_subnet: dict[str, set[str]] = defaultdict(set)

    for line in lines:
        ssh_match = SSH_FAIL_RE.search(line)
        if ssh_match:
            source_ip = _valid_ipv4(ssh_match.group(1))
            if source_ip:
                ssh_failures[source_ip] += 1
                ssh_samples.setdefault(source_ip, line[:220])
        else:
            ip_match = IPV4_RE.search(line)
            source_ip = _valid_ipv4(ip_match.group(1)) if ip_match else None

        if source_ip:
            ip_activity[source_ip] += 1

        for rule, regex in compiled_rules:
            if regex.search(line):
                ip_key = source_ip or "unknown"
                bucket_key = (rule.rule_id, ip_key)
                if bucket_key not in sig_hits:
                    sig_hits[bucket_key] = {
                        "rule": rule,
                        "ip": ip_key,
                        "count": 0,
                        "sample": line[:220],
                    }
                sig_hits[bucket_key]["count"] += 1
                if source_ip:
                    attacking_ips_by_subnet[_to_subnet_24(source_ip)].add(source_ip)

    alerts: list[SecurityAlert] = []

    # 1. Signature alerts (SQLi, XSS, Traversal, Recon)
    for hit in sig_hits.values():
        rule: SignatureRule = hit["rule"]
        ip_key: str = hit["ip"]
        alerts.append(
            SecurityAlert(
                rule_id=rule.rule_id,
                title=rule.name,
                severity=rule.severity,
                category=rule.category,
                source_ip=ip_key,
                subnet_24=_to_subnet_24(ip_key) if ip_key != "unknown" else "unknown",
                count=hit["count"],
                detail=f"{hit['count']} coincidencia(s) detectada(s) desde {ip_key}.",
                sample_line=hit["sample"],
            )
        )

    # 2. SSH Brute Force correlation
    ssh_limit = thresholds["ssh_bruteforce_attempts"]
    for ip, attempts in ssh_failures.items():
        if attempts >= ssh_limit:
            subnet = _to_subnet_24(ip)
            attacking_ips_by_subnet[subnet].add(ip)
            alerts.append(
                SecurityAlert(
                    rule_id="SSH-BRUTE-001",
                    title="Fuerza bruta SSH detectada",
                    severity="HIGH",
                    category="brute_force",
                    source_ip=ip,
                    subnet_24=subnet,
                    count=attempts,
                    detail=f"{attempts} intentos fallidos de autenticación SSH (umbral: {ssh_limit}).",
                    sample_line=ssh_samples.get(ip, ""),
                )
            )

    # 3. Coordinated attack correlation by /24 subnet
    coord_limit = thresholds["subnet_coordinated_ips"]
    for subnet, ips in sorted(attacking_ips_by_subnet.items()):
        if len(ips) >= coord_limit:
            alerts.append(
                SecurityAlert(
                    rule_id="NET-SUBNET-001",
                    title="Actividad maliciosa coordinada desde la misma subred /24",
                    severity="HIGH",
                    category="network_correlation",
                    source_ip=", ".join(sorted(ips)),
                    subnet_24=subnet,
                    count=len(ips),
                    detail=f"{len(ips)} IPs distintas con alertas dentro de la subred {subnet}.",
                )
            )

    # 4. Statistical traffic spike anomaly per IP
    if len(ip_activity) >= 3:
        counts = list(ip_activity.values())
        mean = statistics.mean(counts)
        stdev = statistics.pstdev(counts)
        dynamic_cutoff = max(thresholds["spike_min_requests"], mean + 1.5 * stdev)
        for ip, count in ip_activity.items():
            if count >= dynamic_cutoff:
                alerts.append(
                    SecurityAlert(
                        rule_id="ANOM-SPIKE-001",
                        title="Pico anómalo de tráfico por IP",
                        severity="MEDIUM",
                        category="anomaly",
                        source_ip=ip,
                        subnet_24=_to_subnet_24(ip),
                        count=count,
                        detail=(
                            f"{count} peticiones (media={mean:.1f}, umbral estadístico={dynamic_cutoff:.1f})."
                        ),
                    )
                )

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: (severity_rank.get(a.severity, 9), -a.count, a.rule_id))

    subnet_activity = Counter(_to_subnet_24(ip) for ip in ip_activity.elements())

    return AnalysisReport(
        total_lines=len(lines),
        unique_ips=len(ip_activity),
        high_count=sum(1 for a in alerts if a.severity == "HIGH"),
        medium_count=sum(1 for a in alerts if a.severity == "MEDIUM"),
        low_count=sum(1 for a in alerts if a.severity == "LOW"),
        top_ips=dict(ip_activity.most_common(10)),
        top_subnets_24=dict(subnet_activity.most_common(10)),
        alerts=alerts,
    )


def _sanitize_csv_cell(value: str) -> str:
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{value}"
    return value


def export_alerts_csv(report: AnalysisReport) -> str:
    """Export alerts to UTF-8 CSV (sanitized against spreadsheet formula injection)."""
    buffer = io.StringIO()
    buffer.write("\ufeff")
    writer = csv.writer(buffer)
    writer.writerow(["Regla", "Severidad", "Categoría", "Título", "IP Origen", "Subred /24", "Eventos", "Detalle"])
    for alert in report.alerts:
        writer.writerow(
            [
                alert.rule_id,
                alert.severity,
                alert.category,
                _sanitize_csv_cell(alert.title),
                _sanitize_csv_cell(alert.source_ip),
                alert.subnet_24,
                alert.count,
                _sanitize_csv_cell(alert.detail),
            ]
        )
    return buffer.getvalue()
