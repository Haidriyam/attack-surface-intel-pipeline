![Recon Intelligence DevSecOps CI](https://github.com/Haidriyam/attack-surface-intel-pipeline/actions/workflows/devsecops-ci.yml/badge.svg)

# Attack Surface Intelligence & Exposure Telemetry Pipeline

An automated External Attack Surface Management (EASM) scoring engine and telemetry aggregator that normalizes OSINT reconnaissance data, evaluates risk heuristics, and outputs structured SIEM/SOAR event payloads.

```text
[ Multi-Source OSINT / Recon Ingestion ] ──► [ Telemetry Normalizer ]
                                                       │
                                                       ▼
[ Executive Threat Metrics ] ◄── [ Structured SIEM ] ◄── [ Dynamic Risk Engine ]