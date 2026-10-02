# Threat Intelligence Knowledge

## Purpose

This local knowledge file defines how NEXUS should interpret synthetic threat-intelligence context.

## Indicators

Common indicators include:
- IPv4 addresses
- domains
- URLs
- file hashes
- email addresses
- usernames
- hostnames

## Investigation approach

For each indicator:
1. Identify the indicator type.
2. Find related events in the security dataset.
3. Check whether the indicator is marked malicious, suspicious, or unknown.
4. Identify related threat type or technique.
5. Correlate the indicator with users, assets, and incidents.
6. Record confidence and supporting evidence.

## Important rule

A threat-intelligence match is supporting evidence, not automatic proof of compromise. NEXUS should present the evidence and allow a human analyst to make the final decision.
