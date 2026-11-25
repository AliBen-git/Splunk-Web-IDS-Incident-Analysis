# Splunk Web & IDS Incident Analysis

**SOC investigation portfolio project using Splunk to correlate web server activity with IDS alerts and assess suspicious external activity.**

 > **Project status:** Five matching events have been reviewed in Splunk. Supporting search screenshots are included below.

## Executive overview

This project documents a Splunk investigation of web traffic and IDS alerts associated with the observed IP address `45.33.12.143`.

The search results show **five matching events** on **1 February 2026**, from **09:26:15 to 09:58:40**. The events are split across two indexes:

- `web_access_logs`: 3 events
- `ids_alerts_log`: 2 events

The web events include a SQL-injection-like login request, a request to `/index.html`, and a POST request to `/admin`. The first and third web requests returned HTTP 401; the `/index.html` request returned HTTP 404. Both IDS events were marked Critical.

The available evidence supports a conclusion of suspicious web requests and IDS-detected activity. It does **not** establish successful exploitation, a confirmed C2 session, or system compromise.

## Observed event timeline

| Time (1 Feb 2026) | Source | Observed event | Result |
|---|---|---|---|
| 09:26:15 | Web access | GET `/login.php?user=admin'--`; user agent `sqlmap` | HTTP 401 |
| 09:34:00 | IDS | `ET MALWARE Possible C2 Traffic` | Critical |
| 09:40:50 | Web access | GET `/index.html`; user agent `sqlmap` | HTTP 404 |
| 09:47:55 | Web access | POST `/admin`; user agent `sqlmap` | HTTP 401 |
| 09:58:40 | IDS | `ET SCAN Nmap Scripting Engine` | Critical |

The event details above are transcribed from the supplied Splunk screenshot. The screenshots show the Splunk timestamps but do not explicitly show the timezone.

## Data sources and event distribution

| Index | Events for `45.33.12.143` |
|---|---:|
| `web_access_logs` | 3 |
| `ids_alerts_log` | 2 |
| **Total** | **5** |

The raw event view shows `sourcetype=_json` for both sources. The displayed host field is `Ben`.

A broader screenshot shows a search result set of 240 events and a statistics table with 42 source-IP rows. In that aggregation, `45.33.12.143` has 3 web events and 2 IDS alerts. This broader dataset context should not be confused with the five events filtered for the investigated IP.

## Investigation objectives

- Review web requests associated with the observed IP address.
- Identify suspicious request patterns, including SQL-injection-like input and administrative-area access attempts.
- Interpret HTTP response codes in context.
- Examine IDS alerts and their severity.
- Correlate web and IDS observations by timestamp and source IP.
- Communicate findings while separating observed evidence from assumptions.

## Key analytical considerations

- The request path `/login.php?user=admin'--` and user agent `sqlmap` are indicators of SQL-injection testing or probing; the HTTP 401 response does not show that injection succeeded.
- The POST request to `/admin` returned HTTP 401. This does not demonstrate that administrative access was obtained.
- The `/index.html` request returned HTTP 404.
- `ET MALWARE Possible C2 Traffic` is an IDS alert, not independent confirmation of an established C2 channel.
- `ET SCAN Nmap Scripting Engine` indicates an IDS-detected scan signature; it does not prove exploitation.
- The observed IP address is present as `src_ip` in the displayed events. Attribution, ownership, and intent are not established by these screenshots.

## Splunk investigation screenshots

### 1. Raw events for the investigated IP

![Raw events for 45.33.12.143](screenshots/01-raw-events-target-ip.png)

### 2. Event count by index

![Event count by index](screenshots/02-event-count-by-index.png)

### 3. Broader source-IP context

![Broader source IP overview](screenshots/03-source-ip-overview.png)

### 4. IDS signature overview

![IDS signature overview](screenshots/04-ids-signature-overview.png)

### 5. Correlated web and IDS timeline

![Correlated web and IDS timeline](screenshots/05-correlated-web-ids-timeline.png)

### 6. HTTP status codes and URLs

![HTTP status and URL counts](screenshots/06-http-status-and-urls.png)

### 7. IDS alert details

![IDS alert details](screenshots/07-ids-alert-details.png)

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

## Recommended follow-up evidence

- Review authentication and application logs for successful access or server-side errors.
- Inspect the IDS event details, signature IDs, ports, protocol, and packet/flow evidence.
- Check endpoint telemetry for suspicious process execution, file creation, or persistence.
- Correlate DNS and outbound network connections to validate the possible C2 detection.

## Responsible use

Publish only lab material you are authorised to share. Avoid exposing credentials, tokens, or other secrets.

## Disclaimer

This repository documents an educational Splunk investigation. It does not claim that a real-world compromise occurred or attribute malicious activity to an individual or organisation.

## Author

**AliBen-git**  
Cybersecurity / SOC Analyst portfolio project
