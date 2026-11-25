# SPL Queries – Web & IDS Incident Analysis

## Important note

The supplied incident summary provides the observed IP address, date/time window, event count, HTTP response codes, and two IDS alert names. It does **not** provide the Splunk index, sourcetypes, exact field names, or the original SPL searches.

The searches below are therefore **templates to adapt and validate**, not transcriptions of the original lab searches. Replace the placeholders with field names and index values confirmed in your Splunk environment. Do not claim a search was run until you have executed it and reviewed the results.

## Investigation scope

- Observed IP: `45.33.12.143`
- Date: 1 February 2026
- Time window: 09:26–09:58 (timezone not specified in the supplied summary)
- Supplied event count: 5
- Reported HTTP codes: 401 and 404
- IDS alerts:
  - `ET MALWARE Possible C2 Traffic`
  - `ET SCAN Nmap Scripting Engine`

## 1. Inspect available indexes and sources

Start by identifying the available data rather than guessing the index.

```spl
| eventcount summarize=false
| table index count
| sort -count
```

After identifying likely indexes, inspect their sourcetypes and sources:

```spl
index=<confirmed_index>
| stats count by sourcetype source
| sort -count
```

## 2. Search web events for the observed IP

Replace `<confirmed_web_index>` and `<confirmed_ip_field>` with values confirmed from the raw events.

```spl
index=<confirmed_web_index> "<observed_ip>"
| table _time <confirmed_ip_field> method uri status host user_agent
| sort 0 _time
```

Set the observed value as `<observed_ip>` only after confirming which field contains it. If the field is known, prefer an explicit field filter over a free-text search.

## 3. Review HTTP response codes

After confirming the response field name:

```spl
index=<confirmed_web_index> "<observed_ip>"
| stats count by status
| sort -count
```

To inspect the relevant 401 and 404 records:

```spl
index=<confirmed_web_index> "<observed_ip>" (status=401 OR status=404)
| table _time <confirmed_ip_field> method uri status host
| sort 0 _time
```

Confirm whether the status field is numeric or string-valued in the dataset before using this exact syntax.

## 4. Search for the two reported IDS signatures

Replace the index and signature field with the actual IDS data model fields.

```spl
index=<confirmed_ids_index> "<observed_ip>"
("ET MALWARE Possible C2 Traffic" OR "ET SCAN Nmap Scripting Engine")
| table _time <signature_field> <severity_field> <src_ip_field> <dest_ip_field> <src_port_field> <dest_port_field>
| sort 0 _time
```

Review the full raw events to obtain signature IDs, protocol, ports, sensor, and evidence fields. The alert names alone do not confirm C2 communication or successful exploitation.

## 5. Build an event timeline

Once the source/destination and timestamp fields have been validated, combine the relevant events using a consistent field mapping. A simple first step is to review each source chronologically:

```spl
index=<confirmed_index> "<observed_ip>"
| sort 0 _time
| table _time sourcetype source host
```

A combined timeline should only be built after confirming that the sources use compatible timestamp formats, timezones, and IP direction semantics.

## 6. Validate the reported event count

Use the exact same indexes, IP field/value, and time range as the original investigation:

```spl
index=<confirmed_index> "<observed_ip>"
| stats count
```

The supplied summary reports five events. The query above will only reproduce that count if its scope and filtering match the original search. A free-text search may include or omit events differently from an explicit field filter.

## SPL validation checklist

- Confirm the relevant index names.
- Confirm sourcetypes and source values.
- Inspect raw events before relying on field extraction.
- Confirm the IP field and whether it represents source or destination.
- Confirm the timestamp timezone.
- Confirm the exact names and types of HTTP status, URI, method, severity, and signature fields.
- Record the time picker range and result count.
- Save screenshots of actual search output, with sensitive information removed.

## Results to add after running the searches

For each query, document the exact SPL, actual time range, returned count, representative evidence, interpretation, and screenshot filename. Do not use the supplied incident summary as a substitute for raw event evidence.
