# Screenshots – Web & IDS Incident Analysis

The following seven screenshots document the Splunk investigation. They are ordered to follow the investigation workflow.

| File | Evidence |
|---|---|
| `01-raw-events-target-ip.png` | Five raw events matching `45.33.12.143` |
| `02-event-count-by-index.png` | Three web events and two IDS events |
| `03-source-ip-overview.png` | Broader source-IP aggregation |
| `04-ids-signature-overview.png` | IDS signature distribution across the broader dataset |
| `05-correlated-web-ids-timeline.png` | Combined chronological web/IDS events |
| `06-http-status-and-urls.png` | HTTP status codes and requested URLs |
| `07-ids-alert-details.png` | Two Critical IDS alerts with timestamps |

The repeated IDS screenshot was not included twice.

These screenshots support the observations documented in the incident report. They do not, by themselves, prove successful exploitation, a confirmed C2 session, or system compromise.

Publish only lab material you are authorised to share, and never expose credentials, tokens, or other secrets.
