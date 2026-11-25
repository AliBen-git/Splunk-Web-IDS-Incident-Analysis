# Incident Report – Web & IDS Activity

## 1. Executive summary

A Splunk search identified five events associated with `src_ip=45.33.12.143` on 1 February 2026, from 09:26:15 to 09:58:40. The events were distributed across `web_access_logs` (3 events) and `ids_alerts_log` (2 events).

The web events show a GET request to `/login.php?user=admin'--` with user agent `sqlmap` and HTTP 401, a GET request to `/index.html` with HTTP 404, and a POST request to `/admin` with HTTP 401. The IDS events are `ET MALWARE Possible C2 Traffic` and `ET SCAN Nmap Scripting Engine`, both marked Critical.

The observed activity is suspicious and warrants further investigation. The evidence supplied does not establish successful SQL injection, successful administrative access, a confirmed C2 session, or system compromise.

## 2. Scope and data sources

| Attribute | Value |
|---|---|
| Observed source IP field/value | `src_ip=45.33.12.143` |
| Date | 1 February 2026 |
| First event | 09:26:15 |
| Last event | 09:58:40 |
| Total matching events | 5 |
| `web_access_logs` | 3 |
| `ids_alerts_log` | 2 |
| Sourcetype shown | `_json` |
| Host field shown | `Ben` |
| Splunk time picker shown | All time |

The timezone is not explicitly identified in the screenshots.

## 3. Event timeline

| Time | Source | Event | Result |
|---|---|---|---|
| 09:26:15 | Web | GET `/login.php?user=admin'--`; user agent `sqlmap` | 401 |
| 09:34:00 | IDS | `ET MALWARE Possible C2 Traffic` | Critical |
| 09:40:50 | Web | GET `/index.html`; user agent `sqlmap` | 404 |
| 09:47:55 | Web | POST `/admin`; user agent `sqlmap` | 401 |
| 09:58:40 | IDS | `ET SCAN Nmap Scripting Engine` | Critical |

This timeline is based on the five displayed matching events. It shows temporal order, not necessarily a causal relationship between every event.

## 4. Web traffic findings

Three web access events were returned:

1. **09:26:15 — Login request:** GET `/login.php?user=admin'--`, user agent `sqlmap`, HTTP 401. The URL and user agent are consistent with SQL-injection testing/probing. The response does not show that the injection succeeded.
2. **09:40:50 — Page request:** GET `/index.html`, user agent `sqlmap`, HTTP 404. The requested resource was reported as not found.
3. **09:47:55 — Administrative path:** POST `/admin`, user agent `sqlmap`, HTTP 401. The response does not demonstrate that administrative access was obtained.

The screenshot's status/URL aggregation shows one event for each of the three combinations above.

## 5. IDS findings

Two IDS events were returned:

| Time | Signature | Severity |
|---|---|---|
| 09:34:00 | `ET MALWARE Possible C2 Traffic` | Critical |
| 09:58:40 | `ET SCAN Nmap Scripting Engine` | Critical |

The first is a possible C2-related detection and requires validation using packet/flow and endpoint evidence. The second is a scan-related detection. Neither alert, on its own, confirms successful exploitation or compromise.

## 6. Broader dataset context

A separate Splunk statistics screenshot shows 240 events and 42 source-IP rows in a broader result set. The row for `45.33.12.143` shows 3 web events and 2 IDS alerts. Other source IPs and signatures are also present in that broader dataset.

This broader context suggests that the investigated address is one of several addresses represented in the dataset. The screenshots do not prove that all listed addresses are part of the same incident or share the same intent.

## 7. Assessment

**Finding:** Suspicious web request activity and two Critical IDS detections were observed for `45.33.12.143` during the reviewed time window.

**Confidence:** High that the five events and their displayed fields are present in the supplied Splunk screenshots. Insufficient evidence to conclude that exploitation or compromise occurred.

The available evidence does not establish:
- Successful SQL injection or server-side execution
- Successful administrative authentication
- A confirmed command-and-control connection
- Malware execution or persistence on the host
- Attribution or ownership of the observed IP address

## 8. Recommended follow-up

1. Review application and authentication logs for successful access around the same time.
2. Inspect the full IDS event data, including signature IDs, ports, protocol, sensor, and packet/flow evidence.
3. Review endpoint telemetry for suspicious process execution, file creation, web shell indicators, or persistence.
4. Correlate DNS and outbound network connections to validate the possible C2 alert.
5. Confirm whether the Nmap-related activity was followed by further probing or exploitation attempts.

## 9. Mitigation considerations

- Use parameterised queries and secure input handling in web applications.
- Restrict and monitor administrative endpoints.
- Review authentication controls and alerting for repeated unauthorised requests.
- Validate IDS detections against network context.
- Monitor outbound traffic for potential C2 behaviour.
- Keep internet-facing applications and services patched.

These are general defensive recommendations, not evidence that a specific control failed.

## 10. Limitations

The screenshots show the five matching events and relevant fields but do not provide packet captures, IDS signature IDs, source/destination ports, destination IP, application-side execution evidence, or endpoint telemetry. The timezone is also not specified. These gaps prevent confirmation of successful exploitation or compromise.

## 11. Final conclusion

The Splunk investigation identified three web access events and two Critical IDS alerts associated with `45.33.12.143` on 1 February 2026. The login request and `sqlmap` user agent indicate likely probing activity, while the IDS alerts warrant further analysis. The observed HTTP responses and alert names do not prove that the target was compromised.
