# Investigation Methodology

## 1. Scope

This project documents a Splunk incident-analysis exercise involving correlation of web traffic logs and IDS alerts associated with the IP address `45.33.12.143`.

The supplied summary identifies five events on 1 February 2026 between 09:26 and 09:58. The purpose is to assess the suspicious activity and determine whether the available evidence supports a conclusion about successful exploitation or compromise.

## 2. Supplied observations

The incident summary states that:

- Web logs contained a suspected SQL-injection-like request.
- A request attempted to access an administrative area.
- The noted requests returned HTTP 401.
- Another request returned HTTP 404.
- IDS logs contained two Critical alerts:
  - `ET MALWARE Possible C2 Traffic`
  - `ET SCAN Nmap Scripting Engine`

The source summary does not include raw events, exact URI values, methods, source and destination ports, signature IDs, or the individual timestamp of each observation.

## 3. Investigation procedure

### Step 1 — Define the time window and IP context

Use the supplied date and time window as the initial search scope. Confirm which field in each data source represents the observed IP address. Do not assume that the same field name or direction is used in web and IDS logs.

Record the index, sourcetype, source, timezone, and relevant extracted fields from the actual Splunk environment.

### Step 2 — Examine web access activity

Review the events associated with the observed IP address. Inspect the raw records and, where available, the HTTP method, requested URI, status code, user agent, virtual host, client IP, and destination server.

The supplied summary describes a SQL-injection-like request and access to an administrative area. Treat these as suspicious request patterns, not proof that the application executed injected input or that access was obtained.

### Step 3 — Interpret HTTP response codes

The supplied results mention HTTP 401 and 404 responses.

- **401 Unauthorized:** The request was not authorised under the application's response. Review authentication logs and application behaviour before assessing whether access controls worked as intended.
- **404 Not Found:** The requested resource was not found or was not served at the requested path. Review the request and application context; this response alone does not indicate compromise.

Do not infer a successful exploit from either response code.

### Step 4 — Review IDS alerts

Inspect the two reported Critical alerts:

- `ET MALWARE Possible C2 Traffic`
- `ET SCAN Nmap Scripting Engine`

For each alert, collect the full raw event, signature ID, timestamp, protocol, source and destination addresses and ports, sensor, and any packet/flow evidence provided by the dataset.

The word "Possible" in the C2 alert name matters: verify the alert against network and endpoint evidence before reporting an established C2 channel. Likewise, an Nmap-related scan alert can indicate probing activity, but does not by itself prove exploitation.

### Step 5 — Correlate web and IDS events

Compare event timestamps and network endpoints across the data sources. Confirm whether the IP field refers to a client, source, destination, NAT address, or proxy address in each log.

Build a timeline from individual event records rather than assuming that two alerts and web requests are causally connected merely because they occurred in the same time window.

### Step 6 — Assess impact and confidence

Look for corroborating evidence of successful authentication, application errors, web shell or file creation, suspicious server-side process execution, outbound connections, or unauthorised changes.

Classify each statement as:

- **Observed:** directly present in the supplied event or summary.
- **Assessment:** an interpretation supported by multiple observations.
- **Unconfirmed:** a hypothesis requiring further evidence.

## 4. Evidence handling

For each search, preserve:

- Exact SPL and time picker range
- Index and sourcetype
- Event count and representative raw events
- Relevant timestamps and timezone
- Key fields used for correlation
- Screenshots with sensitive values sanitised
- Interpretation and remaining uncertainty

## 5. Current limitations

The supplied incident summary does not provide the raw five events or complete event-level details. Therefore this document cannot independently determine:

- Whether the IP address was the client, source, or destination in every event
- Exact request paths, methods, payloads, or user agents
- Which server or application received the requests
- The precise timestamps for the individual alerts and web requests
- Whether the possible C2 activity was confirmed
- Whether authentication was successful at any other point
- Whether exploitation, code execution, or system compromise occurred

These items must be validated from the underlying Splunk events and any available endpoint telemetry.
