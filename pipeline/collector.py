"""
Reconnaissance Data Aggregator & Telemetry Normalizer.
Parses multi-source external exposure artifacts into a normalized schema.
"""
from typing import Dict, Any, List


class ReconTelemetryCollector:
    HIGH_RISK_PORTS = {21, 22, 23, 3389, 5432, 27017, 9200}

    @staticmethod
    def normalize_asset(asset_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize raw asset reconnaissance data into structured telemetry.
        """
        domain = asset_record.get("domain", "").lower().strip()
        ip_addresses = asset_record.get("ips", [])
        ports = [int(p) for p in asset_record.get("open_ports", [])]
        dns_sec_enabled = bool(asset_record.get("dnssec", False))
        tls_days_remaining = int(asset_record.get("tls_days_left", 365))

        dangerous_ports = [p for p in ports if p in ReconTelemetryCollector.HIGH_RISK_PORTS]

        return {
            "asset_id": domain or (ip_addresses[0] if ip_addresses else "unknown-target"),
            "domain": domain,
            "ip_addresses": ip_addresses,
            "open_ports": ports,
            "exposed_admin_services": dangerous_ports,
            "tls_days_remaining": tls_days_remaining,
            "dnssec_active": dns_sec_enabled,
        }

    @staticmethod
    def aggregate_perimeter(raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [ReconTelemetryCollector.normalize_asset(rec) for rec in raw_records]