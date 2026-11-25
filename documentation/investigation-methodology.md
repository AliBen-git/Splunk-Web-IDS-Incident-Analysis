# Investigation Methodology

## 1. Scope

This project documents a Splunk investigation correlating web access logs and IDS alerts associated with `src_ip=45.33.12.143`.

The supplied screenshots show five matching events on 1 February 2026, between 09:26:15 and 09:58:40. The time zone is not explicitly displayed.

## 2. Data sources

The screenshots identify two indexes:

| Index | Events for the observed IP | Sourcetype shown |
|---|---:|---|
| `web_access_logs` | 3 | `_json` |
| `ids_alerts_log` | 2 | `_json` |
| **Total** | **5** | |

The displayed host field is `Ben`. Confirm whether this is a lab hostname or a value that should be anonymised before publishing.

## 3. Observed events

| Timestamp | Index | Event details |
|---|---|---|
| 2026-02-01 09:26:15 | `web_access_logs` | GET `/login.php?user=admin'--`, status 401, user agent `sqlmap` |
| 2026-02-01 09:34:00 | `ids_alerts_log` | `ET MALWARE Possible C2 Traffic`, severity Critical |
| 2026-02-01 09:40:50 | `web_access_logs` | GET `/index.html`, status 404, user agent `sqlmap` |
| 2026-02-01 09:47:55 | `web_access_logs` | POST `/admin`, status 401, user agent `sqlmap` |
| 2026-02-01 09:58:40 | `ids_alerts_log` | `ET SCAN Nmap Scripting Engine`, severity Critical |

The raw JSON visible in the screenshots includes `time`, `src_ip`, `method`, `url`, `status`, `user_agent` for web events, and `time`, `src_ip`, `signature`, `severity` for IDS events.

## 4. Investigation steps

### Step 1 — Search all indexes for the observed IP

The screenshot shows the following search:

```spl
index=* "45.33.12.143"
| table _time index sourcetype source host _raw
| sort _time
```

It returned five events. This search established the two contributing indexes and exposed the raw event details.

### Step 2 — Count events by index

The screenshot shows:

```spl
index=* "45.33.12.143"
| stats count by index
| sort - count
```

The result was 3 events in `web_access_logs` and 2 events in `ids_alerts_log`.

### Step 3 — Correlate web and IDS records

The supplied screenshot shows this combined search:

```spl
(index=web_access_logs OR index=ids_alerts_log)
src_ip="45.33.12.143"
| eval event_type=if(index="ids_alerts_log","IDS","Webbtrafik")
| eval detail=coalesce(signature,url)
| eval severity=coalesce(severity,"N/A")
| table _time event_type detail severity method status user_agent
| sort _time
```

It returned five chronological events and made the web/IDS sequence visible in one table.

### Step 4 — Review web response codes and requested URLs

The screenshot shows:

```spl
index=web_access_logs src_ip="45.33.12.143"
| stats count by status url
| sort - count
```

The result contains one event for each of these combinations:

- HTTP 401 — `/admin`
- HTTP 401 — `/login.php?user=admin'--`
- HTTP 404 — `/index.html`

### Step 5 — Inspect IDS alerts

The screenshot shows:

```spl
index=ids_alerts_log src_ip="45.33.12.143"
| table _time signature severity _raw
| sort _time
```

It returned two events:

- 09:34:00 — `ET MALWARE Possible C2 Traffic`, Critical
- 09:58:40 — `ET SCAN Nmap Scripting Engine`, Critical

## 5. Interpretation

The `sqlmap` user-agent value and the login URL containing `admin'--` are consistent with SQL-injection probing. However, the observed HTTP 401 response does not establish successful injection. The POST request to `/admin` also returned 401, and the `/index.html` request returned 404.

The IDS alerts identify suspicious traffic patterns, but the available screenshots do not include packet evidence, signature IDs, ports, or endpoint events. The possible C2 alert therefore remains an alert requiring validation, not proof of a successful C2 session.

## 6. Broader dataset context

A separate screenshot shows 240 events in a broader search and a statistics table with 42 source-IP rows. The row for `45.33.12.143` shows 3 web events and 2 IDS alerts. Another screenshot lists signatures associated with multiple source IPs.

This broader search context suggests the investigated IP is one of several addresses in the dataset. Do not infer that every other listed IP is part of the same incident without additional correlation.

## 7. Limitations

The supplied screenshots do not establish the time zone, destination IP/host direction, source/destination ports, full IDS metadata, packet evidence, successful authentication, application-side execution, or endpoint compromise. Those details require additional log sources and event review.
