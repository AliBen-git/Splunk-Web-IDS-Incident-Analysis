# Screenshots – Web & IDS Incident Analysis

Eight Splunk screenshots were supplied for review in the conversation. They show:

1. Five matching raw events for `45.33.12.143`, including timestamps, indexes, sourcetype, source, host, and raw JSON.
2. Event counts by index: 3 in `web_access_logs` and 2 in `ids_alerts_log`.
3. A broader source-IP statistics view showing 240 events and 42 source-IP rows.
4. A broader signature aggregation view that includes multiple IPs and signatures.
5. A combined five-event web/IDS timeline.
6. A web status and URL count showing 401 for `/admin`, 401 for `/login.php?user=admin'--`, and 404 for `/index.html`.
7. IDS event details showing the two Critical alerts and timestamps.
8. A repeated IDS results view.

## Recommended filenames

When adding the sanitised image files to this folder, use descriptive names such as:

- `01-raw-events-target-ip.png`
- `02-event-count-by-index.png`
- `03-broader-source-ip-context.png`
- `04-broader-signature-context.png`
- `05-correlated-web-ids-timeline.png`
- `06-web-status-and-url-counts.png`
- `07-ids-alert-details.png`

The repeated IDS screenshot is not necessary to publish twice.

## Publication and privacy checks

Before publishing the images, review them for:
- The Splunk account label `Administrator`
- The host value `Ben`
- Other source IP addresses shown in the broader dataset views
- Any sensitive internal host, network, or account information

The broader screenshots display multiple IP addresses, not just the investigated `45.33.12.143`. Mask unrelated addresses if they are not intended to be public. Keep the target value visible only if you are authorised to publish it.

Screenshots should retain enough context to show the search, result count, and relevant fields. Do not alter event values or counts when sanitising.
