# Intruder Payload Scanner with Verifier (Burp Suite Extension)

A Burp Suite context-menu extension that automates payload-based testing using a lightweight “Intruder-like” engine with two execution modes (Sniper / Battering Ram), payload libraries loaded from local JSON files, optional verifier requests, basic response heuristics (expected strings / timing), and Burp Collaborator support.

It is designed to run quick, repeatable payload scans against one or more selected requests, while also supporting advanced workflows such as stored-XSS verification through a local verifier service.

---

## What it does

- Loads payloads from one or more `.json` files placed next to the extension.
- Uses placeholders in the request to inject payloads dynamically.
- Supports two scanning modes:
  - Sniper: injects into one marked position at a time
  - Battering Ram: injects into all marked positions at once
- Supports “Verifier Requests”:
  - you can add one or more extra requests that will be executed after the main request (useful for confirming stored effects)
- Can report issues into Burp Scanner Issues when:
  - the response contains an expected string
  - the response time exceeds a configured threshold
  - Burp Collaborator interactions are observed
  - stored XSS verification detects an alert (via local verifier service)
- Follows HTTP redirects automatically (up to a limit), preserving cookies across redirects.

---

## Burp Integration

Right-click menu entries:

- Scan with Intruder Payload Scanner
- Scan by Category
  - Scan <CategoryName> (auto-generated from loaded payload files)
- Add as Verifier Request
- Remove Verifier Requests

The extension operates on the currently selected messages in Burp (e.g., Repeater / Proxy History / Target items depending on where you invoke it).

---

## Payload files (.json)

The extension auto-detects all `.json` files from the extension directory and loads payload entries from them.

Each JSON file must contain a list of payload objects.

Minimal example structure:

[
  {
    "category": "SQLi",
    "payload": "'",
    "expectedResponse": "SQL syntax",
    "expectedDelay": "2",
    "expectingCollab": false
  }
]

Supported fields per payload entry:

- category (string)
  - used for “Scan by Category” menu
  - if missing, defaults to "Uncategorized"
- payload (string) REQUIRED
  - can include the special token [COLLAB] which will be replaced with a fresh Burp Collaborator payload
- expectedResponse (string, optional)
  - if present and found in response, an issue is reported
- expectedDelay (string/number, optional)
  - if response time is higher than this value (seconds), an issue is reported
- expectingCollab (boolean, optional)
  - if true, Collaborator interactions are checked and reported

---

## Injection placeholder format

The extension injects payloads into places wrapped with the marker:

[{{{EI-PAYLOAD}}}] ... [/{{{EI-PAYLOAD}}}]

Notes:
- The current implementation replaces the whole marker block with the payload.
- In Sniper mode: only one marker occurrence is replaced per iteration.
- In Battering Ram mode: all marker occurrences are replaced at once.
- Marker tags are removed automatically after replacement.

---

## Scanning modes

### Sniper
- Each injection point (marker occurrence) is tested independently.
- Useful for isolating which parameter/location triggers a behavior.

### Battering Ram
- The same payload is injected into all marked positions at once.
- Useful for quickly stress-testing multiple inputs in a single run.

You choose the mode in the configuration dialog before the scan starts.

---

## Verifier Requests (post-actions / confirmation)

You can attach additional requests as “verifiers” that execute after the main request.

Workflow:
1. Select a request → right-click → Add as Verifier Request
2. Repeat to add multiple verifier requests
3. Start scan (normal or category scan)
4. Verifiers are executed after relevant steps (especially used in stored-XSS flow)

Remove all verifiers:
- Remove Verifier Requests

The configuration dialog shows the current number of verifier requests.

---

## Stored XSS category behavior

If a payload entry has category set to:

XSS (STORED)

The extension switches to a special verification flow:
- Sends modified request(s) to a local verifier service at:
  - localhost:7437
- Adds special EI-* headers to the request:
  - EI-Target (scheme://host:port)
  - EI-Method (HTTP method)
  - EI-CSP (currently fixed value)
  - EI-Fragment (only if a URL fragment #... was present in the original raw request line)
- Parses JSON response from the verifier service and reports an issue if:
  - alert_detected is true

Verifier requests are also executed through the same local service to confirm stored effects.

Important detail:
- The extension extracts URL fragments (#fragment) from the raw HTTP request line before Burp parsing, because Burp analyzeRequest may drop fragments. If a fragment is detected, it is removed from the request line and passed via EI-Fragment header.

---

## Redirect handling

For normal (non-stored-XSS) flows, responses are processed with redirect-following logic:
- supports 301, 302, 303, 307, 308
- up to 5 redirects (default)
- keeps track of cookies across redirects:
  - extracts Cookie header from request
  - collects Set-Cookie values from redirects
  - rebuilds Cookie header on subsequent redirect requests
- updates Host header and request line appropriately
- enforces method changes for:
  - 301/302/303 → usually switches to GET for non-GET/HEAD

---

## Dynamic tags

### [increment] tags
You can embed:

[increment]123[/increment]

It will be replaced with an auto-incremented number during scanning.

If the tag contains a number, it adds the current increment value to it.
If empty, it becomes the current increment value.

---

### [REGEXTAG={{{...}}}] tags
You can embed a regex extraction tag:

[REGEXTAG={{{<regex>}}}]

During scanning, the extension will run the regex against the previous response and replace the tag with:
- the first capturing group if present, otherwise the whole match

It supports regex strings that include literal escape sequences coming from clipboard/tools:
- \\r\\n, \\n, \\r, \\t are normalized into real characters before compiling.

If no match is found, the tag is left unchanged and an error is printed to Burp output.

---

## Collaborator support

- The extension creates a Burp Collaborator context on load and generates a payload.
- Any payload string containing [COLLAB] will have it replaced with the generated Collaborator payload.
- If a payload entry has expectingCollab=true:
  - the extension checks for interactions
  - reports an issue if interactions are detected
  - then rotates Collaborator context/payload for subsequent tests

---

## Reporting to Burp Issues

When a condition is met, the extension creates a Burp Scanner Issue with:
- Name: value derived from the payload logic (e.g., "Potential Vulnerability" or "XSS (STORED)")
- Severity: High
- Confidence: Certain
- Evidence: includes the chain of requests/responses executed so far (stored in http_messages_so_far)

---

## Configuration dialog

Before each scan, the extension shows a dialog that allows:
- selecting which payload JSON files to load for this run
- choosing scanning mode (Sniper / Battering Ram)
- viewing the number of configured verifier requests

---

## Installation

1. Burp Suite → Extender → Extensions → Add
2. Type: Python
3. Select the extension .py file
4. Configure Jython 2.7 in Extender → Options → Python Environment
5. Place your payload .json files in the same directory as the extension
6. Load the extension

On load, Burp output shows:
- Intruder Payload Scanner with verifier extension loaded
- Collaborator payload initialized: <...>
