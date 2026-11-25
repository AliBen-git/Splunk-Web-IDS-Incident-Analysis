# SPL Queries – Web & IDS Incident Analysis

The searches in this document are transcribed from the supplied Splunk screenshots. The observed index names and fields are therefore based on the displayed lab results.

## Investigation scope

- Observed source IP: `45.33.12.143`
- Date: 1 February 2026
- Event window: 09:26:15–09:58:40
- Matching events: 5
- Indexes: `web_access_logs` and `ids_alerts_log`
- Sourcetype shown: `_json`

## 1. Find matching events across indexes

```spl
index=* "45.33.12.143"
| table _time index sourcetype source host _raw
| sort _time
```

**Observed result:** 5 events. The raw event table shows 3 web access records and 2 IDS records.

## 2. Count matching events by index

```spl
index=* "45.33.12.143"
| stats count by index
| sort - count
```

**Observed result:**

| Index | Count |
|---|---:|
| `web_access_logs` | 3 |
| `ids_alerts_log` | 2 |

## 3. Correlate web and IDS events in one timeline

```spl
(index=web_access_logs OR index=ids_alerts_log)
src_ip="45.33.12.143"
| eval event_type=if(index="ids_alerts_log","IDS","Webbtrafik")
| eval detail=coalesce(signature,url)
| eval severity=coalesce(severity,"N/A")
| table _time event_type detail severity method status user_agent
| sort _time
```

**Observed result:** 5 events in chronological order.

| Time | Type | Detail | Severity | Method | Status | User agent |
|---|---|---|---|---|---:|---|
| 09:26:15 | Webbtrafik | `/login.php?user=admin'--` | N/A | GET | 401 | sqlmap |
| 09:34:00 | IDS | `ET MALWARE Possible C2 Traffic` | Critical | — | — | — |
| 09:40:50 | Webbtrafik | `/index.html` | N/A | GET | 404 | sqlmap |
| 09:47:55 | Webbtrafik | `/admin` | N/A | POST | 401 | sqlmap |
| 09:58:40 | IDS | `ET SCAN Nmap Scripting Engine` | Critical | — | — | — |

## 4. Count web responses by status and URL

```spl
index=web_access_logs src_ip="45.33.12.143"
| stats count by status url
| sort - count
```

**Observed result:**

| Status | URL | Count |
|---:|---|---:|
| 401 | `/admin` | 1 |
| 401 | `/login.php?user=admin'--` | 1 |
| 404 | `/index.html` | 1 |

## 5. Inspect IDS alert details

```spl
index=ids_alerts_log src_ip="45.33.12.143"
| table _time signature severity _raw
| sort _time
```

**Observed result:**

| Time | Signature | Severity |
|---|---|---|
| 09:34:00 | `ET MALWARE Possible C2 Traffic` | Critical |
| 09:58:40 | `ET SCAN Nmap Scripting Engine` | Critical |

## 6. Broader source-IP aggregation shown in the lab

The supplied screenshots also show a broader search result set of 240 events and a statistics view with 42 source-IP rows. In that aggregation, `45.33.12.143` is shown with 3 web events and 2 IDS alerts.

The exact SPL used for that broader aggregation is not legible in the supplied screenshots, so it is not reconstructed here. The broader results include multiple source IPs and should not be treated as part of this single-IP incident without further evidence.

## Analytical notes

- The first web request contains the URL value `/login.php?user=admin'--` and user agent `sqlmap`. This is consistent with SQL-injection probing, but the HTTP 401 response does not show that the injection succeeded.
- The POST request to `/admin` returned HTTP 401.
- The GET request to `/index.html` returned HTTP 404.
- The IDS alert names and Critical severity are observations; validate the underlying traffic before confirming C2 activity or a successful attack.
- The screenshots show `src_ip` as the field used to filter these events. They do not establish attribution or intent.

## Validation and reproducibility

The screenshots show the time picker set to **All time**. The displayed events have timestamps on 1 February 2026. For reproducibility, record the exact time picker and timezone when rerunning these searches in the lab.
