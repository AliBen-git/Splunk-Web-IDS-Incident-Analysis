# Splunk Web & IDS Incident Analysis

**SOC investigation portfolio project using Splunk to correlate web server activity with IDS alerts and assess suspicious external activity.**

> **Project status:** Initial incident summary documented from the supplied lab results. Detailed SPL searches, raw event evidence, and screenshots should be added when the original searches and event records are available.

## Executive overview

This project documents a Splunk investigation of web traffic and IDS alerts associated with the IP address `45.33.12.143`.

The supplied incident summary reports **five events** on **1 February 2026**, between **09:26 and 09:58**. The web logs included a suspected SQL-injection-like request and an attempt to access an administrative area. Those requests returned HTTP **401**. Another request returned HTTP **404**.

The IDS records contained two Critical alerts:

- `ET MALWARE Possible C2 Traffic`
- `ET SCAN Nmap Scripting Engine`

Taken together, these observations indicate suspicious web and scanning-related activity that merits further investigation. The available summary does **not** establish that an exploit succeeded or that the system was compromised.

## Investigation objectives

- Review web requests associated with the observed IP address.
- Identify suspicious request patterns, including SQL-injection-like input and administrative-area access attempts.
- Interpret HTTP response codes in context.
- Examine IDS alerts and their severity.
- Correlate web and IDS observations by timestamp and source/destination information where available.
- Communicate findings while separating observed evidence from assumptions.

## Observed incident facts

| Item | Supplied lab result |
|---|---|
| Observed IP address | `45.33.12.143` |
| Date | 1 February 2026 |
| Time window | 09:26–09:58 |
| Number of events | 5 |
| Web activity | SQL-injection-like request; administrative-area access attempt; another request |
| HTTP responses | 401 and 404 |
| IDS alert 1 | Critical — `ET MALWARE Possible C2 Traffic` |
| IDS alert 2 | Critical — `ET SCAN Nmap Scripting Engine` |
| Overall assessment | Suspicious activity; compromise not confirmed |

The description supplied for this project does not provide the complete raw events, exact request URIs, HTTP methods, destination host, IDS signature metadata, or the individual timestamp for each of the five events.

## Investigation workflow

1. Scope the relevant time range and identify the IP field used by the web and IDS data.
2. Review matching web access events and inspect request method, URI, status, user agent, and destination host when available.
3. Review IDS alerts and retain signature, severity, source, destination, and event time.
4. Correlate the data sources by time and network endpoints.
5. Determine what the observations support and what additional endpoint or application evidence is needed.
6. Document the incident timeline and defensive recommendations.

## Repository structure

```text
Splunk-Web-IDS-Incident-Analysis/
├── README.md
├── documentation/
│   └── investigation-methodology.md
├── queries/
│   └── spl-queries.md
├── findings/
│   └── incident-report.md
└── screenshots/
    └── README.md
```

## Key analytical considerations

- HTTP 401 indicates that the request was not authorised under the application's response. It does not prove that authentication controls were bypassed.
- HTTP 404 indicates that the requested resource was not found or was not exposed at that path. It is not proof of successful exploitation.
- An IDS alert is a detection requiring validation against its underlying packet/event evidence and surrounding activity.
- The IP address is an observed indicator in the supplied summary. The available data does not independently establish attribution, ownership, or intent.
- A possible C2 alert should be treated as a lead for further investigation, not as confirmation of an established command-and-control channel.

## Recommended follow-up evidence

To strengthen the incident assessment, collect the raw Splunk events and, where available:

- Full web access log records, including request method, URI, response code, user agent, host, and client/server IP fields.
- Full IDS event details, including signature ID, source and destination ports, protocol, packet or flow evidence, and sensor.
- Application, authentication, and reverse-proxy logs for the same time window.
- Endpoint telemetry from the destination server to check for suspicious process execution, file changes, or persistence.
- DNS and network connection telemetry to validate the possible C2 detection.

## Responsible use

Sanitise screenshots and event examples before publishing. Do not expose credentials, tokens, personal data, or sensitive internal host details. Publish only work you are authorised to share.

## Disclaimer

This repository documents an educational Splunk investigation based on the results supplied for the lab. It does not claim that a real-world compromise occurred, and it does not attribute malicious activity to an individual or organisation.

## Author

**AliBen-git**  
Cybersecurity / SOC Analyst portfolio project
