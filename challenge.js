/* Operation NorthStar CTF | Author: PhyN | Password: edit ACCESS_PASSWORD below | Answers: SHA-256 hashes in QUESTIONS array */

if (!window.crypto || !window.crypto.subtle) {
  document.body.innerHTML =
    '<div style="padding:60px 20px;color:#ff6b6b;font-family:monospace;text-align:center;max-width:640px;margin:60px auto;border:1px solid #ff6b6b55;border-radius:8px;background:#1a0d0d">' +
    '<h1 style="color:#ff6b6b;letter-spacing:2px">Web Crypto API Required</h1>' +
    '<p>This challenge uses SHA-256 via the Web Crypto API to validate answers. ' +
    'Your browser either does not support <code>crypto.subtle</code> or the page is being ' +
    'served from an insecure context.</p>' +
    '<p style="color:#aaa">Please open this file in <strong>Chrome 60+</strong>, ' +
    '<strong>Firefox 55+</strong>, <strong>Safari 11+</strong>, or <strong>Edge 79+</strong>, ' +
    'served over <code>https://</code> or <code>file://</code> (or <code>http://localhost</code>).</p>' +
    '</div>';
  throw new Error('Web Crypto API not available');
}

try {
  console.clear();
  console.log(
    '%cSTOP — Read this before you poke around.',
    'color:#ff6b6b;font-size:22px;font-weight:bold;letter-spacing:1px'
  );
  console.log(
    '%cThis is a client-side CTF challenge. Answers are stored as SHA-256 hashes ' +
    'and cannot be read from the QUESTIONS array. Tampering with the page, ' +
    'replacing the hash comparator, or re-writing state in DevTools is against ' +
    'the spirit of the challenge and produces a hollow win.',
    'color:#ffb0b0;font-size:13px;line-height:1.5;max-width:600px;white-space:pre-wrap'
  );
} catch (e) {  }

var ACCESS_PASSWORD = "northstar2024"; // change this string to set a new gate password

const QUESTIONS = [

  {
    id: 1, num: "Q_1", title: "The Inaugural Alarm", diff: "m", diffLabel: "Medium",
    correctHash: "41b437143fd8e94a2731062a6c37ca94a081d9513f71ca7e8f1f1827c80c90c3", format: "X.X.X.X",
    text: `Perimeter intrusion detection sensors began flagging anomalous activity mere minutes into the collection window. The very first alert, a generic ICMP echo probe directed at the organisation's public-facing IP address, originated from an external host that would later be implicated in far more consequential activity, including web application exploitation attempts classified at elevated severity. Subsequent examination of the intrusion detection log confirms that this same address triggered a Priority 1 signature for SQL injection approximately two and a half hours later. Identify the source IP address responsible for this inaugural detection event.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Open the Snort alert log (<code>IDS-BO-EDGE/snort_alert.log</code>) and examine the chronologically ordered entries.</li>
<li>The first recorded alert at <code>09/10-13:10:57</code> documents a <code>PROTOCOL-ICMP PING BSDtype</code> event originating from a single external address.</li>
<li>Extract the source IP from the <code>SRC -&gt; DST</code> notation.</li>
<li>Corroborate by locating the SQL Injection UNION SELECT alert (signature <code>1:2009714:9</code>, Priority 1) which shares this same source address.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Open Snort alert log and view chronological entries
less IDS-BO-EDGE/snort_alert.log

# Step 2: Extract the first timestamped alert
head -1 IDS-BO-EDGE/snort_alert.log
# → 09/10-13:10:57.609 [1:366:1] PROTOCOL-ICMP PING BSDtype ... &lt;SRC_IP_A&gt; -&gt; 45.83.221.5

# Step 3: Extract just the source IP
head -1 IDS-BO-EDGE/snort_alert.log | grep -oP '\d+\.\d+\.\d+\.\d+(?=\s*-&gt;)'
# → &lt;SRC_IP_A&gt;

# Step 4: Corroborate — this same IP triggered SQL Injection P1 later
grep '&lt;SRC_IP_A&gt;' IDS-BO-EDGE/snort_alert.log
# → Shows both ICMP PING (13:10) and SQL Injection UNION SELECT (15:43) — same actor</pre>
<div class="tip-box"><strong>Tip:</strong> A host that opens with ICMP reconnaissance and proceeds to targeted SQL injection demonstrates deliberate progression through a structured kill chain, distinguishing it from opportunistic scanners that probe indiscriminately.</div>`
  },

  {
    id: 2, num: "Q_2", title: "The Scanner's Fingerprint", diff: "m", diffLabel: "Medium",
    correctHash: "f9a8f0a70b0315c2f4365f48ff46f5937e4cc18edf632eb628d53dab086bdc06", format: "Text",
    text: `Approximately forty minutes after the initial ICMP probes subsided, an automated vulnerability assessment tool commenced a systematic enumeration of the organisation's web-facing application. The scanner's signature was unmistakably embedded within the HTTP User-Agent header of every probe request, revealing both the tool's identity and its precise version number. The operator made no effort to conceal the scanner through evasion parameters, leaving the tool's full identifier plainly visible in access logs. Provide the exact tool name and version as it appeared in the request headers.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Search web access records for User-Agent strings containing the substring "Nikto", a well-known open-source web server scanner.</li>
<li>The Apache combined-format access log reveals: <code>Mozilla/5.00 (&lt;scanner vX.Y.Z&gt;) (Evasions:None)</code>.</li>
<li>Extract the tool identifier from the parenthesised portion.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Search web access records for known scanner User-Agent strings
grep -iE 'nikto|nessus|burp|sqlmap|acunetix' WEB-BO-01.northstar-branch.local/web_access.log

# Step 2: Extract the tool identifier from the first Nikto line
grep 'Nikto' WEB-BO-01.northstar-branch.local/web_access.log | head -1
# → &lt;SRC_IP_B&gt; ... "Mozilla/5.00 (&lt;scanner vX.Y.Z&gt;) (Evasions:None) (Test:380195)"

# Step 3: Parse out the tool name and version from User-Agent
grep 'Nikto' WEB-BO-01.northstar-branch.local/web_access.log | head -1 | grep -oP 'Nikto/[^)]+\)' | tr -d ')'
# → &lt;scanner vX.Y.Z&gt;

# Step 4: Verify the scanner identity via Zeek HTTP log
grep 'Nikto' ZEEK-BO-CORE/http.json | python3 -c "import json,sys; [print(json.loads(l).get('user_agent','')) for l in sys.stdin]" | head -1
# → Mozilla/5.00 (&lt;scanner vX.Y.Z&gt;) (Evasions:None) (Test:380195)</pre>
<div class="tip-box"><strong>Tip:</strong> The Nikto family of web server scanners is widely documented in defensive literature. The "(Evasions:None)" parameter confirms the operator made no attempt to disguise the tool's identity — a telltale indicator of unsophisticated or rushed reconnaissance methodology.</div>`
  },

  {
    id: 3, num: "Q_3", title: "The Backdoor Gambit", diff: "m", diffLabel: "Medium",
    correctHash: "c34be0e9c2f0a0a62c32f38d90388cb00615f4e6550b99b2763f8d811184b096", format: "X.X.X.X",
    text: `Intrusion detection systems assign severity classifications to each signature based on the potential impact of the detected activity. During the vulnerability scanning phase, a specific signature triggered at the maximum priority level — Priority 1 — indicating an attempt to access a well-known web-based database administration interface frequently targeted by attackers seeking to compromise backend database systems. The source address responsible for this alert had already been observed conducting wide-ranging enumeration of the web server's directory structure. Determine the IP address that prompted this highest-severity detection.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Filter Snort alerts for entries classified at Priority 1.</li>
<li>Locate the earliest Priority 1 event — this corresponds to signature <code>1:2015737:5</code>, "ET WEB_SERVER PHPMyAdmin BackDoor Access".</li>
<li>Extract the source IP from the connection tuple preceding the arrow in the alert notation.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Filter Snort alerts for maximum severity (Priority 1)
grep 'Priority: 1' IDS-BO-EDGE/snort_alert.log

# Step 2: Locate the earliest Priority 1 event — PHPMyAdmin BackDoor
grep 'Priority: 1' IDS-BO-EDGE/snort_alert.log | head -1
# → 09/10-13:50:09 [1:2015737:5] ET WEB_SERVER PHPMyAdmin BackDoor Access [Priority: 1] {TCP} &lt;SRC_IP_B&gt;:57720 -&gt; 45.83.221.5:80

# Step 3: Extract the source IP address
grep 'Priority: 1' IDS-BO-EDGE/snort_alert.log | head -1 | grep -oP '\d+\.\d+\.\d+\.\d+(?=\s*-&gt;)'
# → &lt;SRC_IP_B&gt;

# Step 4: Cross-validate — same IP appears in web access log for phpMyAdmin probe
grep '&lt;SRC_IP_B&gt;.*php[Mm]y[Aa]dmin' WEB-BO-01.northstar-branch.local/web_access.log
# → GET /phpMyAdmin/ HTTP/1.1 301 — confirmed probe from scanner</pre>
<div class="tip-box"><strong>Tip:</strong> PHPMyAdmin is a ubiquitous MySQL administration tool that, if exposed without authentication, provides attackers with a direct conduit to the database layer. Detection of access attempts is categorised at maximum severity in the Emerging Threats ruleset because it nearly always indicates intentional exploitation.</div>`
  },

  {
    id: 4, num: "Q_4", title: "The Configuration Lure", diff: "m", diffLabel: "Medium",
    correctHash: "c34be0e9c2f0a0a62c32f38d90388cb00615f4e6550b99b2763f8d811184b096", format: "X.X.X.X",
    text: `As the automated scanner traversed the web application directory structure, one particular probe targeted a file conventionally employed by modern web frameworks to store environment-specific configuration parameters — values that frequently include database connection strings, API encryption keys, and third-party service credentials. The intrusion detection platform generated a dedicated signature for this probe, while the web server access record confirmed a GET request for the very same resource. What external IP address was responsible for this sensitive configuration file access attempt?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Search web access records for requests targeting filenames conventionally associated with environment configuration storage.</li>
<li>The request for <code>/.env</code> appears with the Nikto scanner User-Agent.</li>
<li>Cross-validate using the Snort alert log: signature <code>1:2034567:2</code>, "ET WEB_SERVER .env File Access Attempt", confirms the same source IP.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Identify requests targeting sensitive configuration files
grep -iE '\.(env|config|ini|yml|yaml|json|bak|sql|git)' WEB-BO-01.northstar-branch.local/web_access.log | grep -v 'assets'

# Step 2: Isolate the .env access specifically
grep '\.env ' WEB-BO-01.northstar-branch.local/web_access.log
# → &lt;SRC_IP_B&gt; GET /.env HTTP/1.1 301

# Step 3: Extract source IP
grep '\.env ' WEB-BO-01.northstar-branch.local/web_access.log | awk '{print $1}' | head -1
# → &lt;SRC_IP_B&gt;

# Step 4: Corroborate via Snort (dedicated .env signature)
grep '2034567' IDS-BO-EDGE/snort_alert.log
# → [1:2034567:2] ET WEB_SERVER .env File Access Attempt ... &lt;SRC_IP_B&gt; -&gt; 45.83.221.5:80</pre>
<div class="tip-box"><strong>Tip:</strong> The .env file convention originates from the Laravel PHP framework and has been adopted by numerous frameworks. Its exposure is catalogued under CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory — and represents one of the most frequently exploited configuration vulnerabilities in modern web applications.</div>`
  },

  {
    id: 5, num: "Q_5", title: "The Token Forge", diff: "m", diffLabel: "Medium",
    correctHash: "4feb84f23663b00875fba792d8bdc045c8346202a95259392dadb38ffdb4ce64", format: "Text",
    text: `Having moved beyond passive reconnaissance, the adversary identified and actively exploited an application programming interface endpoint whose sole purpose was to issue authentication bearer tokens to legitimate service consumers. A series of POST requests directed at this endpoint returned HTTP 200 status codes accompanied by substantial response bodies — in one instance exceeding forty-six kilobytes — containing what circumstantial evidence strongly suggests were valid session tokens. Specify the complete URI path of the authentication endpoint that was abused for credential harvesting.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Identify POST requests in web access records that returned HTTP 200 responses with response bodies exceeding tens of thousands of bytes.</li>
<li>The endpoint <code>&lt;API_AUTH_ENDPOINT&gt;</code> appears multiple times, each receiving a successful response from external IP addresses.</li>
<li>Cross-reference with proxy access records to confirm that the User-Agent strings are programme identifiers rather than browser signatures.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Identify POST requests with unusually large response bodies
awk '$6=="\"POST" && $9==200 && $10>10000' WEB-BO-01.northstar-branch.local/web_access.log

# Step 2: Focus on authentication-related endpoints
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log
# → 184.247.38.121 POST &lt;API_AUTH_ENDPOINT&gt; HTTP/1.1 200 46047
# → 69.109.145.67  POST &lt;API_AUTH_ENDPOINT&gt; HTTP/1.1 200 773

# Step 3: Extract the endpoint path pattern
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log | awk '{print $7}' | head -1
# → &lt;API_AUTH_ENDPOINT&gt;

# Step 4: Verify external origin via Zeek HTTP log
grep 'auth/token' ZEEK-BO-CORE/http.json | python3 -c "
import json,sys
for l in sys.stdin:
    d=json.loads(l)
    print(f\"{d.get('id.orig_h','?')} -&gt; {d.get('host','?')}{d.get('uri','?')} status={d.get('status_code','?')} bytes={d.get('response_body_len','?')}\")"</pre>
<div class="tip-box"><strong>Tip:</strong> Authentication endpoints that issue tokens to unauthenticated external requesters represent a critical deficiency aligned with OWASP API2:2023 — Broken Authentication. The 200 response code confirms the server processed and fulfilled the request rather than rejecting it with 401 or 403.</div>`
  },

  {
    id: 6, num: "Q_6", title: "The Automation Signature", diff: "m", diffLabel: "Medium",
    correctHash: "a53d9a2a74743627526e61ab7f8f2e9c37eb8ae3889c971012656d0c2002b75e", format: "Text",
    text: `The requests targeting the token issuance endpoint exhibited a distinctive characteristic that categorically distinguished them from organic browser traffic: their User-Agent header identified a programme library commonly employed for constructing HTTP requests in Python-based automation scripts. This library — the de facto standard for HTTP operations in the Python ecosystem — is ubiquitous in data science workflows and, regrettably, in countless offensive security toolkits. Its presence in an API call originating from outside the organisation's network perimeter is diagnostically abnormal. Provide the complete User-Agent string used by the token-harvesting actor.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Examine the User-Agent field of POST requests to the <code>&lt;API_AUTH_ENDPOINT&gt;</code> endpoint in the web access log.</li>
<li>Note the complete absence of browser identifiers such as "Chrome", "Firefox", "Safari", or "Edge".</li>
<li>The value <code>&lt;PYTHON_HTTP_LIB_VERSION&gt;</code> identifies the requests library, version 2.31.0.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Isolate POST requests to the authentication endpoint
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log

# Step 2: Extract User-Agent strings (not browser signatures)
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log | grep -oP '"[^"]+"$' | head -1
# → "&lt;PYTHON_HTTP_LIB_VERSION&gt;"

# Step 3: Verify this is NOT a browser — check for absence of Chrome/Firefox/Safari/Edge
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log | grep -viE 'Chrome|Firefox|Safari|Edge' | awk '{print $1, $NF}' | head -1
# → 184.247.38.121 "&lt;PYTHON_HTTP_LIB_VERSION&gt;"

# Step 4: Cross-reference with proxy — same UA from external IP
grep 'python-requests' PROXY-BO-01.northstar-branch.local/proxy_access.log 2&gt;/dev/null | head -3
# → Confirms external automated HTTP traffic through corporate proxy</pre>
<div class="tip-box"><strong>Tip:</strong> The Python requests library is the de facto standard for HTTP operations in the Python ecosystem. While it is a legitimate development tool, its appearance in external-to-internal API requests — particularly those targeting authentication endpoints — is a high-confidence indicator of automated exploitation activity.</div>`
  },

  {
    id: 7, num: "Q_7", title: "The Silent Acknowledgment", diff: "m", diffLabel: "Medium",
    correctHash: "27badc983df1780b60c2b3fa9d3a19a00e46aac798451f0febdca52920faaddf", format: "integer",
    text: `Every successful exploitation attempt imprints a trail of HTTP status codes that document the server's disposition toward each request. When the external actor submitted a POST to the authentication endpoint from an address never previously associated with the organisation's API consumers, the server responded not with a 401 Unauthorised — which would indicate insufficient credentials — nor with a 403 Forbidden — which would suggest explicit denial — but with a code signifying that the request had been processed and its payload delivered successfully. What three-digit HTTP status code did the server return to this unauthorised token request?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Locate POST requests to <code>&lt;API_AUTH_ENDPOINT&gt;</code> in the web access log.</li>
<li>Extract the HTTP status code field — positioned between the request string and the response byte count in the Apache combined log format.</li>
<li>The value <code>&lt;STATUS_CODE&gt;</code> confirms the server fulfilled the request and returned the token payload to the external requester.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Locate POST requests to the token endpoint
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log

# Step 2: Extract the HTTP status code (field 9 in Apache combined format)
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log | awk '{print $1, $7, $9, $10}'
# → 184.247.38.121 &lt;API_AUTH_ENDPOINT&gt; &lt;STATUS_CODE&gt; 46047
# → 69.109.145.67  &lt;API_AUTH_ENDPOINT&gt; &lt;STATUS_CODE&gt; 773

# Step 3: Verify — the &lt;STATUS_CODE&gt; means server fulfilled the request (should have been 401 or 403)
grep 'POST &lt;API_AUTH_ENDPOINT&gt;' WEB-BO-01.northstar-branch.local/web_access.log | awk '{print $9}' | sort | uniq -c
# → All return &lt;STATUS_CODE&gt; — no auth required!

# Step 4: Compare with legit API calls (check for 401/403 patterns elsewhere)
grep 'api/v1' WEB-BO-01.northstar-branch.local/web_access.log | awk '{print $9}' | sort | uniq -c | sort -rn
# → &lt;STATUS_CODE&gt; dominates — no access control on API endpoints</pre>
<div class="tip-box"><strong>Tip:</strong> An HTTP &lt;STATUS_CODE&gt; response to an unauthenticated token request confirms that no middleware, reverse proxy, or WAF rule intercepted the transaction. The endpoint is effectively an anonymous token dispenser — a state of configuration that should immediately trigger an incident response procedure independent of any ongoing intrusion investigation.</div>`
  },

  {
    id: 8, num: "Q_8", title: "The Unlikely Courier", diff: "m", diffLabel: "Medium",
    correctHash: "b0070024f6e41cc307c9035a06049e9356f15769c4668fe83e31d67b4e9c5e51", format: "X.X.X.X",
    text: `Several hours into the incident, network telemetry captured a sequence of API calls that superficially appeared indistinguishable from legitimate application traffic. However, closer inspection of the source addressing revealed that these requests emanated from an internal workstation — a host residing squarely within the corporate LAN — using a command-line HTTP client typically reserved for server-side scripting. No legitimate business process would route workstation-originated curl requests directly against DMZ-hosted API endpoints. Trace the pivot to its origin: to which IP address was this workstation assigned?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Filter web access records for entries whose User-Agent field begins with the string "curl/", indicating command-line HTTP tool invocation.</li>
<li>Note the source IP — it belongs to the 10.44.10.0/24 subnet, confirming an internal workstation origin.</li>
<li>The compromised workstation made repeated POST requests to <code>/api/v1/data</code> and <code>/api/v2/events</code>, endpoints served exclusively by the DMZ web server.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Identify non-browser HTTP clients (curl, wget, python-requests)
grep -E 'curl/|Wget/|python-requests' WEB-BO-01.northstar-branch.local/web_access.log

# Step 2: Filter for curl specifically — reveals command-line pivoting
grep 'curl/' WEB-BO-01.northstar-branch.local/web_access.log | awk '{print $1, $6, $7, $9, $10}'
# → &lt;WORKSTATION_IP&gt; POST /api/v1/data 200 16461
# → &lt;WORKSTATION_IP&gt; POST /api/v2/events 200 41959
# → &lt;WORKSTATION_IP&gt; POST /api/v1/data 200 28880

# Step 3: Confirm internal origin — IP belongs to workstation subnet
echo "&lt;WORKSTATION_IP&gt;" | grep -E '^10\.44\.10\.'
# → &lt;WORKSTATION_IP&gt; — confirmed inside workstation segment

# Step 4: Cross-reference — check if this host appears in Zeek conn for DMZ access
grep '&lt;WORKSTATION_IP&gt;.*10\.44\.30\.10' ZEEK-BO-CORE/conn.json | python3 -c "
import json,sys
for l in sys.stdin:
    d=json.loads(l)
    print(f\"src={d.get('id.orig_h')}:{d.get('id.orig_p')} dst={d.get('id.resp_h')}:{d.get('id.resp_p')} proto={d.get('proto','?')} state={d.get('conn_state','?')}\")"
# → Confirms direct workstation-to-DMZ connections — network segmentation violation</pre>
<div class="tip-box"><strong>Tip:</strong> Workstations in the 10.44.10.0/24 segment should never communicate directly with DMZ-hosted services. The presence of curl-generated requests from this subnet constitutes a clear network segmentation violation and warrants immediate investigation as a potential RCE or credential-theft pivot point.</div>`
  },

  {
    id: 9, num: "Q_9", title: "The Phantom Operator", diff: "m", diffLabel: "Medium",
    correctHash: "b23a6a8439c0dde5515893e7c90c1e3233b8616e634470f20dc4928bcf3609bc", format: "Text",
    text: `As the adversary attempted to extend their reach deeper into the internal infrastructure, endpoint telemetry documented a failed remote access attempt traversing a path that should never exist in normal operations. The connection originated from the DMZ web server and targeted the internal proxy server over SSH. The authentication attempt presented a username that does not correspond to any provisioned account in the organisation's identity directory — a string that reads as though it were a default or placeholder credential. What username was submitted during this unsuccessful SSH authentication?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Examine the proxy server's system log for SSH authentication failures whose source IP matches the DMZ web server (10.44.30.10).</li>
<li>Locate entries containing the phrase "Invalid user" recorded by the sshd daemon.</li>
<li>The username <code>&lt;INVALID_USERNAME&gt;</code> appears in the log line: <code>Invalid user &lt;INVALID_USERNAME&gt; from 10.44.30.10 port 37793</code>.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Search proxy server syslog for SSH authentication failures
grep -E 'Failed|Invalid user' PROXY-BO-01.northstar-branch.local/syslog.log

# Step 2: Filter for connections originating from DMZ web server (10.44.30.10)
grep -E 'Failed|Invalid user' PROXY-BO-01.northstar-branch.local/syslog.log | grep '10\.44\.30\.10'
# → Invalid user &lt;INVALID_USERNAME&gt; from 10.44.30.10 port 37793
# → Failed password for invalid user &lt;INVALID_USERNAME&gt; from 10.44.30.10 port 37793

# Step 3: Extract the username presented during authentication
grep 'Invalid user' PROXY-BO-01.northstar-branch.local/syslog.log | grep '10\.44\.30\.10' | grep -oP 'user \K\S+'
# → &lt;INVALID_USERNAME&gt;

# Step 4: Timeline — check surrounding events for context
grep -A2 -B2 '14:52:2[5-9]' PROXY-BO-01.northstar-branch.local/syslog.log | head -20
# → Shows the full auth attempt: connection, failure, disconnect within 4 seconds</pre>
<div class="tip-box"><strong>Tip:</strong> The submitted username is not a legitimate identity on any standard Linux distribution. This may represent a default credential test, a typographical error in an attacker's automation script, or a deliberate probe designed to elicit verbose logging that reveals the server's authentication stack.</div>`
  },

  {
    id: 10, num: "Q_10", title: "The Corporate Gatekeeper", diff: "m", diffLabel: "Medium",
    correctHash: "582cff1d9cd20ceb2c0ce9f5585406104fbf87bc6598643842862f781f181e40", format: "domain.ltd",
    text: `The organisation's forward proxy — a Squid deployment mediating all outbound web traffic — maintained an access control policy that explicitly forbade connections to certain categories of websites. During the incident window, an authenticated user who had been implicated in extensive SSH pivot activity attempted to establish a CONNECT tunnel to a social news aggregation and discussion platform, only to have the request met with a hard denial. The proxy access record documents both the user's identity and the proxy action taken. What destination hostname was explicitly rejected by the corporate proxy policy?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Parse proxy access records for entries where the <code>proxy_action</code> field equals "deny" and the requesting user is the compromised account.</li>
<li>Extract the hostname from the CONNECT method request line.</li>
<li>The domain <code>&lt;SOCIAL_NEWS_DOMAIN&gt;</code> was blocked with a 403 HTTP status and the <code>proxy_action=deny</code> annotation.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Identify proxy access denials for the compromised user
grep 'nina.kapoor' PROXY-BO-01.northstar-branch.local/proxy_access.log | grep -E 'deny|403'

# Step 2: Extract the denied domain from CONNECT tunnel requests
grep 'nina.kapoor' PROXY-BO-01.northstar-branch.local/proxy_access.log | grep 'proxy_action=deny' | grep -oP 'CONNECT \K[^ ]+' | sed 's/:443$//'
# → &lt;SOCIAL_NEWS_DOMAIN&gt;
# → brynwell.io

# Step 3: Get the full denied request details
grep 'nina.kapoor.*deny' PROXY-BO-01.northstar-branch.local/proxy_access.log | head -1
# → 10.44.10.24 NORTHSTAR-BRANCH\nina.kapoor [10/Sep/2024:13:15:26] "CONNECT &lt;SOCIAL_NEWS_DOMAIN&gt;:443" 403 ...
# → proxy_action=deny ssl_bump=terminate

# Step 4: Check if other users were also denied the same domain (policy test pattern)
grep 'reddit' PROXY-BO-01.northstar-branch.local/proxy_access.log
# → Only nina.kapoor attempted the domain — targeted test of proxy enforcement</pre>
<div class="tip-box"><strong>Tip:</strong> While a denied social-news destination may appear innocuous, a blocked request during an active compromise period merits scrutiny — the attacker may have been testing the proxy's enforcement boundaries to identify permissible egress channels for data exfiltration.</div>`
  },

  {
    id: 11, num: "Q_11", title: "The Dual Identity", diff: "m", diffLabel: "Medium",
    correctHash: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", format: "integer",
    text: `The adversary employed multiple authentication mechanisms when pivoting from the compromised workstation to the DMZ infrastructure. Examining SSH daemon records reveals that different public key algorithms — and consequently different cryptographic identities — were presented during successful authentication events across the two target servers. This suggests either the compromise of multiple private keys or a deliberate operational security practice of using distinct credentials for each target. How many unique SSH public key algorithms were utilised across all successful key-based authentications originating from the internal workstation?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Extract accepted public key entries from the web server's system log for connections originating from 10.44.10.24.</li>
<li>Extract accepted public key entries from the proxy server's system log for the same source address.</li>
<li>Identify the distinct key algorithms: ED25519 was presented to the web server, while ECDSA was offered to the proxy server.</li>
<li>These represent two distinct elliptic curve families, hence two unique algorithm types.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Collect all successful publickey authentications from compromised workstation
grep 'Accepted publickey' WEB-BO-01.northstar-branch.local/syslog.log PROXY-BO-01.northstar-branch.local/syslog.log | grep '10\.44\.10\.24'

# Step 2: Extract the SSH key algorithm and fingerprint from each
grep 'Accepted publickey' WEB-BO-01.northstar-branch.local/syslog.log PROXY-BO-01.northstar-branch.local/syslog.log | grep '10\.44\.10\.24' | grep -oP 'ssh2: \K\S+'
# → ED25519 SHA256:BcdBXtmvIsOxxZDVFwLULsVITFtfP5by65fcRL5X5Np  (WEB-BO-01)
# → ECDSA SHA256:5dZozoxPkzWB/LF1A4hQyNwnINPrzKoIcX+DavYxZYV  (PROXY-BO-01)

# Step 3: Count unique key algorithms
grep 'Accepted publickey' WEB-BO-01.northstar-branch.local/syslog.log PROXY-BO-01.northstar-branch.local/syslog.log | grep '10\.44\.10\.24' | grep -oP 'ssh2: \K\S+' | cut -d' ' -f1 | sort -u | wc -l
# → &lt;KEY_ALGO_COUNT&gt;

# Step 4: List the distinct algorithms
grep 'Accepted publickey' WEB-BO-01.northstar-branch.local/syslog.log PROXY-BO-01.northstar-branch.local/syslog.log | grep '10\.44\.10\.24' | grep -oP 'ssh2: \K\S+' | cut -d' ' -f1 | sort -u
# → ECDSA
# → ED25519</pre>
<div class="tip-box"><strong>Tip:</strong> ED25519 (Twisted Edwards curve) and ECDSA (NIST P-256/P-384/P-521 curves) are computationally incompatible. The use of separate keys per target host limits the blast radius of any single key compromise — a tradecraft indicator consistent with advanced persistent threat operational security practices.</div>`
  },

  {
    id: 12, num: "Q_12", title: "The Perimeter Rejected", diff: "h", diffLabel: "Hard",
    correctHash: "19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7", format: "integer",
    text: `The web server's host-based firewall — a Linux netfilter implementation enforcing an ingress deny-by-default policy — silently discarded unsolicited connection attempts throughout the incident window. Connection requests from various external source addresses targeting an array of well-known service ports were intercepted and blocked at this boundary. How many distinct, globally routable external IP addresses — excluding RFC 1918 private address space — were summarily rejected by the server's UFW subsystem over the course of the entire collection period?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Parse the web server's system log for entries containing the "UFW BLOCK" kernel message.</li>
<li>Extract the source address from the <code>SRC=</code> field of each blocked connection record using a regular expression.</li>
<li>Filter out addresses belonging to RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16.</li>
<li>Count the number of unique addresses in the remaining set.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Extract all UFW kernel block messages from the web server syslog
grep 'UFW BLOCK' WEB-BO-01.northstar-branch.local/syslog.log | wc -l
# → Total: several hundred blocks

# Step 2: Parse the SRC= field from each block entry
grep 'UFW BLOCK' WEB-BO-01.northstar-branch.local/syslog.log | grep -oP 'SRC=\K[\d.]+' | sort | uniq -c | sort -rn
# → Shows frequency per source IP

# Step 3: Filter out RFC 1918 private addresses (keep only globally routable IPs)
grep 'UFW BLOCK' WEB-BO-01.northstar-branch.local/syslog.log | grep -oP 'SRC=\K[\d.]+' | grep -vE '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' | sort -u
# → 145.78.103.167
# → 156.32.3.55
# → &lt;SRC_IP_A&gt;
# → 185.249.5.220
# → 206.122.31.20
# → 37.75.195.175
# → 38.186.148.245
# → 45.33.74.51
# → 74.172.69.175

# Step 4: Count unique external IPs
grep 'UFW BLOCK' WEB-BO-01.northstar-branch.local/syslog.log | grep -oP 'SRC=\K[\d.]+' | grep -vE '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' | sort -u | wc -l
# → &lt;UNIQUE_IP_COUNT&gt;</pre>
<div class="tip-box"><strong>Tip:</strong> The nine external IPs that triggered UFW blocks share substantial overlap with addresses later detected by the Snort intrusion prevention system and the Cisco ASA stateful firewall — a cross-source correlation that strengthens confidence in the hostile nature of the activity.</div>`
  },

  {
    id: 13, num: "Q_13", title: "The Injection Courier", diff: "h", diffLabel: "Hard",
    correctHash: "41b437143fd8e94a2731062a6c37ca94a081d9513f71ca7e8f1f1827c80c90c3", format: "X.X.X.X",
    text: `Among the numerous intrusion detection signatures triggered throughout the incident, the Unified Snort Alert for Structured Query Language injection — specifically a UNION SELECT variant — represented one of the most severe threats to the application data layer. This technique enables an attacker to append arbitrary queries to a vulnerable input parameter, potentially exposing the entire contents of backend database tables. The signature was classified at Priority 1, the highest severity tier in the Emerging Threats ruleset. The source address responsible had been active since the earliest moments of the collection window, having first appeared as the originator of an ICMP probe. Identify the IP address behind this critical injection attempt.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Search the Snort alert log for entries containing the string "UNION SELECT", which is canonical to SQL injection detection signatures.</li>
<li>Note the priority classification of Priority 1, confirming critical severity as defined by the Emerging Threats ruleset.</li>
<li>Extract the source IP from the connection tuple preceding the arrow symbol in the alert notation.</li>
<li>Cross-reference this IP with the first Snort alert of the day — the same address initiated ICMP reconnaissance at 13:10:57.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Find SQL injection-related alerts in the Snort log
grep -iE 'sql|union|injection' IDS-BO-EDGE/snort_alert.log

# Step 2: Focus on the UNION SELECT variant (signature 1:2009714:9, Priority 1)
grep 'UNION SELECT' IDS-BO-EDGE/snort_alert.log
# → 09/10-15:43:44 [1:2009714:9] ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT [Priority: 1] {TCP} &lt;SRC_IP_A&gt;:54362 -&gt; 45.83.221.5:80
# → 09/10-18:50:52 [1:2009714:9] ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT [Priority: 1] {TCP} 45.33.74.51:58283 -&gt; 45.83.221.5:80

# Step 3: Extract source IP from the first (earliest) alert
grep 'UNION SELECT' IDS-BO-EDGE/snort_alert.log | head -1 | grep -oP '\d+\.\d+\.\d+\.\d+(?=\s*-&gt;)'
# → &lt;SRC_IP_A&gt;

# Step 4: Cross-reference with Zeek conn — find the connection tuple
grep '&lt;SRC_IP_A&gt;' ZEEK-BO-CORE/conn.json | python3 -c "
import json,sys
for l in sys.stdin:
    d=json.loads(l)
    print(f\"ts={d['ts']} src={d['id.orig_h']}:{d['id.orig_p']} dst={d['id.resp_h']}:{d['id.resp_p']} state={d['conn_state']} proto={d.get('proto','?')}\")"
# → Shows S0 (connection attempt, no response) — confirming the probe hit but no data returned

# Step 5: Corroborate with ASA firewall — same connection appeared there too
grep '&lt;SRC_IP_A&gt;.*54362' FW-BO-EDGE/cisco_asa.log | head -2
# → ASA Built inbound TCP for this exact tuple, then teardown by TCP FINs</pre>
<div class="tip-box"><strong>Tip:</strong> UNION-based injection is categorised under CWE-89 and is among the most pervasive web application vulnerabilities tracked by the OWASP Top Ten. While modern ORMs and parameterised queries have substantially reduced its prevalence, legacy PHP applications — particularly those employing manual string concatenation for query construction — remain acutely vulnerable.</div>`
  },

  {
    id: 14, num: "Q_14", title: "The Data Drain", diff: "h", diffLabel: "Hard",
    correctHash: "5cb18066c0184cf20ce01c394d236f576620713c230492a080fc56ba31e3e487", format: "integer",
    text: `Once the attacker had established a conduit for extracting information from the backend systems, they executed a sequence of POST requests against the application's primary data retrieval endpoint. Each successful invocation returned a substantive response body to an external address, effectively siphoning structured information out of the organisation's web-facing infrastructure. Individual payloads ranged from approximately ten thousand to upwards of forty-two thousand bytes. Calculate the aggregate volume — in bytes — of all response bodies returned through the /api/v1/data endpoint to POST requests that concluded with an HTTP 200 status code during the incident window.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Filter web access records for lines matching the pattern "POST /api/v1/data" AND HTTP status code 200.</li>
<li>Extract the response size field — positioned immediately after the HTTP status code in the Apache combined log format.</li>
<li>Sum all extracted byte counts.</li>
<li>Exclude any requests where the status code is not 200, as these represent redirections or errors that did not return data.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Identify POST requests to /api/v1/data with successful responses
grep 'POST /api/v1/data' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 '

# Step 2: Display source IP, status, and response size for each
grep 'POST /api/v1/data' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | awk '{printf "%-18s %s %s bytes\n", $1, $9, $NF}'
# → 126.172.93.158    200 42714 bytes
# → 184.247.38.121    200 30709 bytes
# → &lt;WORKSTATION_IP&gt;       200 16461 bytes
# → &lt;WORKSTATION_IP&gt;       200 28880 bytes
# → 69.109.145.67     200 10302 bytes
# → 182.213.36.103    200 14508 bytes

# Step 3: Sum all response bytes
grep 'POST /api/v1/data' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | awk '{sum += $NF} END {print "TOTAL bytes exfiltrated via /api/v1/data:", sum}'
# → TOTAL bytes exfiltrated via /api/v1/data: &lt;TOTAL_BYTES_DATA&gt;

# Step 4: Separate internal vs external sources
echo "--- EXTERNAL ---" &amp;&amp; grep 'POST /api/v1/data' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | grep -v '^10\.' | awk '{sum+=$NF} END {print sum}'
echo "--- INTERNAL ---" &amp;&amp; grep 'POST /api/v1/data' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | grep '^10\.' | awk '{sum+=$NF} END {print sum}'</pre>
<div class="tip-box"><strong>Tip:</strong> The response size field in the Apache combined format is the last space-delimited token on each line. The pattern " 200 " (with leading and trailing spaces) is essential for precise matching, as it prevents false positives from status codes like 2000 or values containing the digits 200 within other fields.</div>`
  },

  {
    id: 15, num: "Q_15", title: "The Service Cycle", diff: "h", diffLabel: "Hard",
    correctHash: "4a972c1dbd377b87215bad546149dc4f9a547bb437b3721553330151dc0c8339", format: "command line",
    text: `Post-exploitation activity on the compromised web server included the execution of a specific system administration command whose invocation during an active intrusion is diagnostically significant. This command terminated and reinitialised the daemon responsible for remote administrative shell access — a manoeuvre that would accomplish the dual objective of activating any configuration changes surreptitiously introduced into the daemon's configuration directory while simultaneously severing any forensic monitoring instruments that had attached to the daemon process. Provide the exact command line that was executed to restart this critical service.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Examine the shell command history belonging to the user account that was active on the web server during the incident window.</li>
<li>Search for invocations of systemctl targeting service units whose name suggests remote access functionality.</li>
<li>The command <code>systemctl restart &lt;DAEMON_NAME&gt;</code> appears at timestamp 1725989065, which corresponds to approximately 18:04 UTC on the incident date.</li>
<li>Note that a sudo session for the admin user was opened on the same host roughly twenty minutes earlier, establishing the necessary privilege context for this operation.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Search bash history for service management commands
grep -E 'systemctl|service|restart|reload' WEB-BO-01.northstar-branch.local/bash_history/nina.kapoor.bash_history

# Step 2: Locate the sshd restart specifically — note the timestamp
grep '&lt;DAEMON_NAME&gt;' WEB-BO-01.northstar-branch.local/bash_history/nina.kapoor.bash_history
# → #1725989065
# → systemctl restart &lt;DAEMON_NAME&gt;

# Step 3: Convert Unix timestamp to human-readable time
date -d @1725989065 -u
# → Tue Sep 10 18:04:25 UTC 2024

# Step 4: Cross-reference with syslog — check for sudo session around that time
grep -A5 -B5 '18:04\|18:05\|18:22' WEB-BO-01.northstar-branch.local/syslog.log | grep -E 'sudo|sshd'
# → 18:22:29 sudo: session opened for user admin — privilege escalation 18 min before restart
# → 18:26:30 sshd: session closed for nina.kapoor — session terminates after restart

# Step 5: Check if sshd config was modified (look for filesystem events near restart time)
grep -E '18:0[0-5]' WEB-BO-01.northstar-branch.local/syslog.log | grep -i ssh</pre>
<div class="tip-box"><strong>Tip:</strong> Restarting &lt;DAEMON_NAME&gt; during an intrusion is a textbook anti-forensic technique. The new daemon instance rotates log buffers, detaches from any monitoring processes that had bound to the original process ID, and loads the complete configuration from /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/, including any files the attacker may have placed in those directories.</div>`
  },

  {
    id: 16, num: "Q_16", title: "The Firewall's Silent Witness", diff: "h", diffLabel: "Hard",
    correctHash: "8b6cd7c429e83373dbd412f43d7422c0c4a127d93d0f2ad15909f0c2a3e7b320", format: "integer",
    text: `The Cisco ASA perimeter firewall maintained a detailed connection table throughout the incident window, logging the establishment and teardown of every TCP session that traversed the security boundary. When a connection initiator sends a SYN packet but receives no response — or when the response is filtered before reaching the initiator — the firewall records a specific teardown reason in its syslog output. Throughout the incident window, a considerable number of inbound connection attempts terminated in this manner, as external scanners probed ports that were not open on the destination server. How many TCP connections were torn down by the firewall with a "SYN Timeout" disposition?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Access the Cisco ASA syslog output and filter for teardown messages, identified by message ID <code>%ASA-6-302014</code>.</li>
<li>Count the occurrences of the string "SYN Timeout" within the teardown reason field.</li>
<li>Do not include connections terminated by "TCP FINs", "TCP Reset-O", or "TCP Reset-I", as these represent normal or reset-terminated sessions rather than unanswered connection attempts.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Extract all ASA connection teardown messages (message ID 302014)
grep '302014.*Teardown' FW-BO-EDGE/cisco_asa.log | wc -l
# → Total teardowns: several thousand

# Step 2: Categorize by teardown reason — count each type
echo "SYN Timeout:" &amp;&amp; grep '302014.*Teardown' FW-BO-EDGE/cisco_asa.log | grep -c 'SYN Timeout'
echo "TCP FINs:" &amp;&amp; grep '302014.*Teardown' FW-BO-EDGE/cisco_asa.log | grep -c 'TCP FINs'
echo "TCP Reset-O:" &amp;&amp; grep '302014.*Teardown' FW-BO-EDGE/cisco_asa.log | grep -c 'TCP Reset-O'
echo "TCP Reset-I:" &amp;&amp; grep '302014.*Teardown' FW-BO-EDGE/cisco_asa.log | grep -c 'TCP Reset-I'

# Step 3: Isolate SYN Timeout count — unanswered connection attempts
grep '302014.*Teardown' FW-BO-EDGE/cisco_asa.log | grep -c 'SYN Timeout'
# → &lt;SYN_TIMEOUT_COUNT&gt;

# Step 4: Calculate scan ratio — SYN Timeouts / Total Teardowns
python3 -c "
import sys,re
total=0; syn=0
for l in sys.stdin:
    if '302014' in l and 'Teardown' in l:
        total+=1
        if 'SYN Timeout' in l: syn+=1
print(f'SYN Timeout: {syn}/{total} = {syn/total*100:.1f}% of all teardowns')
" &lt; FW-BO-EDGE/cisco_asa.log
# → SYN Timeout: &lt;SYN_TIMEOUT_COUNT&gt;/2270 = 38.1% of all teardowns — strong scanning indicator</pre>
<div class="tip-box"><strong>Tip:</strong> SYN Timeout teardowns indicate that the firewall forwarded the initial SYN packet but the destination either did not respond or the response was blocked by an intermediate device. A high ratio of SYN Timeout to successfully established connections is characteristic of port scanning activity — in this dataset, &lt;SYN_TIMEOUT_COUNT&gt; of 2270 teardowns fall into this category, a proportion that strongly corroborates the scanning hypothesis.</div>`
  },

  {
    id: 17, num: "Q_17", title: "The Proxy Sentinel", diff: "h", diffLabel: "Hard",
    correctHash: "15f83025fe124a5fafebd33aef52c1138b3a673c50a8401ce0cf404b38aceb20", format: "Text",
    text: `Midway through the incident window, a service account with elevated privileges initiated a command that cycled the corporate proxy daemon, a Squid instance responsible for mediating all outbound web traffic from the internal network. Restarting this service would transiently disrupt connectivity for every internal user while simultaneously applying any configuration modifications that had been placed in the daemon's configuration hierarchy. The timing of this restart, occurring during a period of heightened SSH pivot activity, warrants investigation into whether the proxy configuration was deliberately altered to facilitate data exfiltration through previously restricted channels. What username was recorded as the initiator of this service restart?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Search the proxy server's system log for sudo session invocations that target the Squid service.</li>
<li>Locate entries where the command field contains "squid" and the authentication module is pam_unix or sudo.</li>
<li>The log records that user <code>&lt;SERVICE_ACCOUNT&gt;</code> (UID 2214) executed <code>/bin/systemctl restart squid</code> with root privileges at 15:03:18 UTC.</li>
<li>Cross-reference this with the proxy access log to note that the restart occurred during a window of heavy SSH activity from the compromised workstation.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Search proxy server syslog for Squid-related entries
grep -i squid PROXY-BO-01.northstar-branch.local/syslog.log

# Step 2: Filter for sudo or systemctl invocations targeting Squid
grep -i squid PROXY-BO-01.northstar-branch.local/syslog.log | grep -E 'sudo|COMMAND'

# Step 3: Extract the username that initiated the restart
grep -i 'restart squid' PROXY-BO-01.northstar-branch.local/syslog.log
# → &lt;SERVICE_ACCOUNT&gt; : TTY=pts/2 ; PWD=/srv/app ; USER=root ; COMMAND=/bin/systemctl restart squid
grep -B1 'restart squid' PROXY-BO-01.northstar-branch.local/syslog.log | grep 'sudo' | grep -oP 'sudo \S+ - - \K\S+' | head -1
# → &lt;SERVICE_ACCOUNT&gt;

# Step 4: Check bash history for the same user
grep 'squid' PROXY-BO-01.northstar-branch.local/bash_history/nina.kapoor.bash_history
# → systemctl is-active squid — nina.kapoor checked Squid status before restart

# Step 5: Timeline — what else happened at ~15:03?
grep '15:03' PROXY-BO-01.northstar-branch.local/syslog.log | grep -v 'kernel\|irqbalance\|rsyslog' | head -20
# → Shows &lt;SERVICE_ACCOUNT&gt; sudo at 15:03:18, plus nina.kapoor SSH sessions before and after</pre>
<div class="tip-box"><strong>Tip:</strong> The &lt;SERVICE_ACCOUNT&gt; service identity (UID 2214) is provisioned for automated maintenance tasks. A manual sudo invocation from this account during an active security incident deviates from its established behavioural profile and should be treated as potential credential compromise rather than assumed legitimate activity.</div>`
  },

  {
    id: 18, num: "Q_18", title: "The Defensive Reconnaissance", diff: "h", diffLabel: "Hard",
    correctHash: "2220f29d8512003efe387fdd475dbaa62d3b2f43afab9949999f44d8950e8c53", format: "command line",
    text: `Shell command history recovered from the internal proxy server revealed that an authenticated operator devoted substantial effort to examining the server's network security configuration. Among the reconnaissance commands executed was a specific invocation of the Linux netfilter administration tool that enumerated every active firewall rule in purely numeric format — suppressing Domain Name System resolution to accelerate execution — thereby exposing the complete ingress and egress access control list governing the host's network interfaces. Reproduce the exact command line employed for this firewall ruleset inspection.`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Search the shell command history file belonging to the user account that was active on the proxy server during the incident period.</li>
<li>Look for invocations of iptables — the canonical Linux netfilter administration utility.</li>
<li>The exact command <code>iptables &lt;LIST_AND_NUMERIC_FLAGS&gt;</code> combines the -L flag, which lists all chains and rules, with the -n flag, which outputs addresses and ports in numeric form to skip DNS reverse lookups.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Search bash history for network reconnaissance commands
grep -E 'iptables|ip |ss |netstat|tcpdump|nmap|ifconfig' PROXY-BO-01.northstar-branch.local/bash_history/nina.kapoor.bash_history

# Step 2: Isolate the exact iptables invocation
grep 'iptables' PROXY-BO-01.northstar-branch.local/bash_history/nina.kapoor.bash_history
# → iptables &lt;LIST_AND_NUMERIC_FLAGS&gt;

# Step 3: Understand the flags — -L lists all rules, -n suppresses DNS
echo "iptables &lt;LIST_AND_NUMERIC_FLAGS&gt;: Lists all chains and rules with numeric addresses (no reverse DNS)"

# Step 4: Find all recon commands in the same history for context
grep -E 'grep|iptables|ss -|last|who|w |hostname|dmesg|free|systemctl' PROXY-BO-01.northstar-branch.local/bash_history/nina.kapoor.bash_history
# → iptables &lt;LIST_AND_NUMERIC_FLAGS&gt;           (firewall inspection)
# → ss -s                    (socket statistics)
# → ss -ltnp | grep squid    (listening services check)
# → grep -i 'failed password' /var/log/auth.log | tail -20  (auth log review)
# → grep -i 'session opened' /var/log/auth.log | tail -20   (session enumeration)</pre>
<div class="tip-box"><strong>Tip:</strong> The combination of -L (list) and -n (numeric) constitutes the quintessential iptables reconnaissance invocation. An operator running this command is actively enumerating the host's defensive posture, most commonly to identify permissive egress rules that could facilitate data exfiltration or restrictive ingress rules that might block command-and-control callback channels.</div>`
  },

  {
    id: 19, num: "Q_19", title: "The Exfiltration Sum", diff: "h", diffLabel: "Hard",
    correctHash: "14a5d5827e99ed55bffb951d27310f12aacc2aab143e8c45af1e187d9af22094", format: "integer",
    text: `Throughout the incident, the adversary employed two distinct API endpoints — one designed for data retrieval and another for event ingestion — to extract structured information from the web application's backend systems. Each successful POST request returned a response body to an address outside the organisation's network perimeter, with individual payloads spanning from several hundred to over forty-six thousand bytes. Establishing the precise extent of data loss is essential for regulatory disclosure assessments, stakeholder notification, and downstream forensic scoping. What is the combined total volume — expressed in bytes — of all successful POST response bodies served through the /api/v1/data and /api/v2/events endpoints?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Compute the subtotal for <code>/api/v1/data</code>: sum all response byte counts for POST requests returning HTTP 200 (&lt;TOTAL_BYTES_DATA&gt; bytes).</li>
<li>Compute the subtotal for <code>/api/v2/events</code>: sum all response byte counts for POST requests returning HTTP 200 (95852 bytes).</li>
<li>Add the two subtotals: &lt;TOTAL_BYTES_DATA&gt; + 95852 = &lt;TOTAL_BYTES_COMBINED&gt;.</li>
<li>Include only requests that received a 200 status code; requests returning 301 (redirect) or other non-success codes indicate the server did not fulfil the data request.</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Show successful POSTs to both endpoints (baseline)
grep -E 'POST /api/v1/(data|v2/events)' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 '

# Step 2: Compute per-endpoint subtotals
echo "=== /api/v1/data ===" &amp;&amp; grep 'POST /api/v1/data' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | awk '{sum+=$NF} END {print sum " bytes"}'
echo "=== /api/v2/events ===" &amp;&amp; grep 'POST /api/v2/events' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | awk '{sum+=$NF} END {print sum " bytes"}'

# Step 3: Compute combined total
grep -E 'POST /api/v1/(data|v2/events)' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | awk '{sum+=$NF} END {print "COMBINED TOTAL:", sum, "bytes"}'
# → COMBINED TOTAL: &lt;TOTAL_BYTES_COMBINED&gt; bytes

# Step 4: Breakdown by source IP to show attribution
grep -E 'POST /api/v1/(data|v2/events)' WEB-BO-01.northstar-branch.local/web_access.log | grep ' 200 ' | awk '{ips[$1]+=$NF} END {for(ip in ips) printf "%-18s %s bytes\n", ip, ips[ip]}' | sort -k2 -rn
# → Shows which external/internal IPs extracted how much data

# Step 5: Note — this excludes Google Drive exfil (proxy) and Cloudflare session data</pre>
<div class="tip-box"><strong>Tip:</strong> This figure represents only the data directly returned through API responses logged by the web server. It excludes any data that may have been exfiltrated through the Google Drive CONNECT tunnel observed in proxy access records, as well as any information accessible through the Cloudflare dashboard session. The true scope of data loss may substantially exceed this baseline calculation.</div>`
  },

  {
    id: 20, num: "Q_20", title: "The Detection Catalogue", diff: "h", diffLabel: "Hard",
    correctHash: "9400f1b21cb527d7fa3d3eabba93557a18ebe7a2ca4e471cfe5e4c5b4ca7f767", format: "integer",
    text: `The intrusion detection system maintained by the organisation's perimeter security infrastructure issued alerts throughout the incident window, cataloguing each detection event with a unique three-component signature identifier in the format gid:sid:rev — representing the generator identifier, signature identifier, and revision number, respectively. These signatures spanned diverse threat categories, from generic ICMP events and reconnaissance scanning to specific web application attack patterns. How many distinct signature identifiers — counting unique gid:sid:rev tuples — appeared in the intrusion detection log over the full six-hour collection period?`,
    writeup: `<h4>Investigation Steps</h4>
<ol>
<li>Parse the Snort alert log and extract every bracketed signature identifier matching the pattern <code>[gid:sid:rev]</code>.</li>
<li>De-duplicate the extracted identifiers, treating each unique three-component tuple as a distinct detection signature.</li>
<li>Count the resulting set.</li>
<li>The &lt;UNIQUE_SIG_COUNT&gt; unique signatures span four classification categories: icmp-event (4 signatures), attempted-recon (8 signatures), web-application-attack (5 signatures), and web-application-activity (2 signatures).</li>
</ol>
<h4>CLI — Full Investigation Workflow</h4>
<pre># Step 1: Extract all Snort signature identifiers (gid:sid:rev format)
grep -oP '\[\K\d+:\d+:\d+' IDS-BO-EDGE/snort_alert.log | sort | uniq -c | sort -rn
# → Shows frequency of each unique signature

# Step 2: Count distinct signature IDs
grep -oP '\[\K\d+:\d+:\d+' IDS-BO-EDGE/snort_alert.log | sort -u | wc -l
# → &lt;UNIQUE_SIG_COUNT&gt;

# Step 3: List each signature with its human-readable name and classification
grep -oP '\[\K\d+:\d+:\d+' IDS-BO-EDGE/snort_alert.log | sort -u | while read sig; do
  alert_count=$(grep -c "$sig" IDS-BO-EDGE/snort_alert.log)
  sig_name=$(grep "$sig" IDS-BO-EDGE/snort_alert.log | head -1 | grep -oP '\] \K[^\[]+(?=\[)' | xargs)
  classification=$(grep "$sig" IDS-BO-EDGE/snort_alert.log | head -1 | grep -oP 'Classification: \K[^\]]+' | xargs)
  priority=$(grep "$sig" IDS-BO-EDGE/snort_alert.log | head -1 | grep -oP 'Priority: \K\d+')
  printf "%-25s %-50s %-30s P%s (%dx)\n" "$sig" "$sig_name" "$classification" "$priority" "$alert_count"
done

# Step 4: Summarize by classification category
grep -oP 'Classification: \K[^\]]+' IDS-BO-EDGE/snort_alert.log | sort | uniq -c | sort -rn
# → icmp-event: 23
# → attempted-recon: &lt;ATTEMPTED_RECON_ALERTS&gt;
# → web-application-attack: 11
# → web-application-activity: 4</pre>
<div class="tip-box"><strong>Tip:</strong> The diversity of signatures activated — spanning ICMP probes, port scanning, directory enumeration, vulnerability scanning, SQL injection, PHP file upload attempts, and credential brute-forcing — confirms that the adversary employed a multi-vector approach aligned with a structured cyber kill chain methodology rather than relying on a single exploitation technique.</div>`
  }
];

for (let i = 0; i < QUESTIONS.length; i++) Object.freeze(QUESTIONS[i]);
Object.freeze(QUESTIONS);

const STORAGE_KEY = 'northstar_progress_v1';
const MAX_ATTEMPTS = 3;

let state = {
  unlocked: false,

  answers: {}
};

function saveState() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch(e) {}
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        state.unlocked = !!parsed.unlocked;
        state.answers = parsed.answers || {};
      }
    }
  } catch(e) {}
}

function clearState() {
  state = { unlocked: false, answers: {} };
  try { localStorage.removeItem(STORAGE_KEY); } catch(e) {}
}

async function hashAnswer(s) {
  const normalized = String(s).trim().toLowerCase().replace(/\s+/g, ' ');
  const buf = new TextEncoder().encode(normalized);
  const digest = await window.crypto.subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

const gate = document.getElementById('gate');
const gateInput = document.getElementById('gateInput');
const gateErr = document.getElementById('gateErr');
const gateForm = document.getElementById('gateForm');

function tryUnlock(pwd) {
  if (pwd === ACCESS_PASSWORD) {
    state.unlocked = true;
    saveState();
    gate.style.display = 'none';
    showChallenge();
  } else {
    gateErr.textContent = '✗ Incorrect password';
    gateInput.classList.add('error');
    gateInput.value = '';
    setTimeout(() => {
      gateInput.classList.remove('error');
      gateInput.focus();
    }, 500);
  }
}

gateForm.addEventListener('submit', (e) => {
  e.preventDefault();
  tryUnlock(gateInput.value);
});

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function renderTOC() {
  const grid = document.getElementById('tocGrid');
  grid.innerHTML = QUESTIONS.map(q => {
    const a = state.answers[q.id];
    let cls = '', icon = '○';
    if (a) {
      if (a.correct) { cls = 'solved'; icon = '✓'; }
      else { cls = 'wrong'; icon = '✗'; }
    }
    return `<a href="#q${q.id}" class="${cls}" data-qid="${q.id}">
      <span class="qnum">${q.num.replace('Q_','Q')}</span>
      <span class="qtitle">${escapeHTML(q.title)}</span>
      <span class="qicon">${icon}</span>
    </a>`;
  }).join('');
}

function renderCards() {

  document.querySelectorAll('.ans-form').forEach(form => {
    if (form.dataset.bound) return;
    form.dataset.bound = '1';
    const qid = parseInt(form.dataset.qid, 10);

    if (!document.querySelector(`.attempts[data-attempts="${qid}"]`)) {
      const counter = document.createElement('div');
      counter.className = 'attempts';
      counter.dataset.attempts = String(qid);
      const entry = state.answers[qid];
      const attempts = entry ? (entry.attempts || 0) : 0;
      const locked = !!(entry && entry.locked);
      counter.innerHTML =
        '<span class="attempts-label">Attempts:</span>' +
        `<span class="attempts-num">${attempts}/${MAX_ATTEMPTS}</span>`;
      if (locked) counter.classList.add('locked');
      form.parentNode.insertBefore(counter, form);
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = form.querySelector('.ans-input');
      const btn = form.querySelector('.ans-btn');

      if (btn) btn.disabled = true;
      if (input) input.disabled = true;
      try {
        await submitAnswer(qid, input ? input.value : '');
      } finally {

      }
    });
  });

  document.querySelectorAll('.card').forEach(card => {
    if (card.dataset.ctxBlocked) return;
    card.dataset.ctxBlocked = '1';
    card.addEventListener('contextmenu', e => e.preventDefault());
  });
}

function toggleCard(qid) {
  const card = document.querySelector(`.card[data-qid="${qid}"]`);
  card.classList.toggle('open');
}

function expandAll() {
  document.querySelectorAll('.card').forEach(c => c.classList.add('open'));
}

function collapseAll() {
  document.querySelectorAll('.card').forEach(c => c.classList.remove('open'));
}

function normalize(s) {
  return String(s).trim().toLowerCase().replace(/\s+/g, ' ');
}

function getCardEls(qid) {
  return {
    input:  document.querySelector(`.ans-input[data-input="${qid}"]`),
    btn:    document.querySelector(`.ans-btn[data-btn="${qid}"]`),
    fb:     document.querySelector(`.feedback[data-feedback="${qid}"]`),
    card:   document.querySelector(`.card[data-qid="${qid}"]`),
    status: document.querySelector(`[data-status="${qid}"]`),
    counter:document.querySelector(`.attempts[data-attempts="${qid}"]`)
  };
}

function setAttemptsUI(qid, attempts, locked) {
  const c = document.querySelector(`.attempts[data-attempts="${qid}"]`);
  if (!c) return;
  const num = c.querySelector('.attempts-num');
  if (num) num.textContent = `${attempts}/${MAX_ATTEMPTS}`;
  c.classList.toggle('locked', !!locked);
}

function buildWriteupHTML(qid, q, isCorrect) {

  if (isCorrect) {
    return `<button type="button" class="writeup-toggle" onclick="toggleWriteup(${qid})">Show Investigation Writeup ▾</button>` +
           `<div class="wu-ctn" data-wu="${qid}">${q.writeup}</div>`;
  }

  return `<div class="writeup-locked">🔒 Investigation writeup locked — solve the question correctly to unlock the methodology and full evidence walkthrough.</div>`;
}

function buildCorrectFeedback(qid, q) {
  return `<span class="label">✓ CORRECT</span> — your answer is accepted.<br>` +
         buildWriteupHTML(qid, q, true);
}

function buildWrongRetryFeedback(qid, q, entry) {
  const remaining = MAX_ATTEMPTS - entry.attempts;
  const yourAns = escapeHTML(entry.user || '(empty)');
  return `<span class="label">✗ INCORRECT</span> — your answer <span class="user-strike">${yourAns}</span> does not match.<br>` +
         `<span class="tip">Attempts remaining: ${remaining}/${MAX_ATTEMPTS}. ` +
         `Re-examine the evidence files referenced in the question to deduce the correct value.</span>` +
         buildWriteupHTML(qid, q, false);
}

function buildWrongLockedFeedback(qid, q, entry) {
  const yourAns = escapeHTML(entry.user || '(empty)');
  return `<span class="label">🔒 MAXIMUM ATTEMPTS (${MAX_ATTEMPTS}) REACHED</span><br>` +
         `<span class="user-strike">${yourAns}</span> did not match the expected value.<br>` +
         `<span class="lock-msg">🔒 Investigation writeup locked — the answer requires evidence from the evidence files and can only be unlocked by solving the question correctly.</span>` +
         buildWriteupHTML(qid, q, false);
}

async function submitAnswer(qid, userValue) {
  const q = QUESTIONS.find(x => x.id === qid);
  if (!q) return;

  if (!state.answers[qid]) {
    state.answers[qid] = { attempts: 0, correct: false, locked: false, user: '' };
  }
  const entry = state.answers[qid];

  if (entry.correct || entry.locked) return;

  const userTrim = String(userValue || '').trim();
  if (!userTrim) {
    const els = getCardEls(qid);
    if (els.input) { els.input.disabled = false; els.input.focus(); }
    if (els.btn)   { els.btn.disabled = false; }
    return;
  }

  entry.attempts = (entry.attempts || 0) + 1;
  entry.user = userTrim;
  saveState();
  setAttemptsUI(qid, entry.attempts, false);

  let inputHash;
  try {
    inputHash = await hashAnswer(userTrim);
  } catch (err) {

    entry.attempts -= 1;
    saveState();
    setAttemptsUI(qid, entry.attempts, false);
    const els = getCardEls(qid);
    if (els.input) els.input.disabled = false;
    if (els.btn)   els.btn.disabled = false;
    console.error('hashAnswer failed:', err);
    alert('Internal error: could not compute answer hash. Please retry.');
    return;
  }
  const isCorrect = (inputHash === q.correctHash);

  if (isCorrect) {
    entry.correct = true;
  } else if (entry.attempts >= MAX_ATTEMPTS) {
    entry.locked = true;
  }
  saveState();

  const els = getCardEls(qid);

  if (isCorrect) {
    if (els.input) { els.input.disabled = true; els.input.classList.remove('wrong'); els.input.classList.add('correct'); }
    if (els.btn) els.btn.disabled = true;
    if (els.card) { els.card.classList.remove('wrong'); els.card.classList.add('correct'); }
    if (els.status) { els.status.textContent = '✓'; els.status.style.color = '#00ff88'; }
    if (els.fb) {
      els.fb.className = 'feedback correct show';
      els.fb.innerHTML = buildCorrectFeedback(qid, q);
    }
  } else if (entry.locked) {
    setAttemptsUI(qid, entry.attempts, true);
    if (els.input) { els.input.disabled = true; els.input.classList.add('wrong'); }
    if (els.btn) els.btn.disabled = true;
    if (els.card) els.card.classList.add('wrong');
    if (els.status) { els.status.textContent = '✗'; els.status.style.color = '#ff6b6b'; }
    if (els.fb) {
      els.fb.className = 'feedback wrong show';
      els.fb.innerHTML = buildWrongLockedFeedback(qid, q, entry);
    }
  } else {

    if (els.input) {
      els.input.disabled = false;
      els.input.value = '';
      els.input.classList.add('wrong');
      els.input.focus();
    }
    if (els.btn) els.btn.disabled = false;
    if (els.card) els.card.classList.add('wrong');
    if (els.status) { els.status.textContent = '✗'; els.status.style.color = '#ff6b6b'; }
    if (els.fb) {
      els.fb.className = 'feedback wrong show';
      els.fb.innerHTML = buildWrongRetryFeedback(qid, q, entry);
    }
  }

  updateScore();
  renderTOC();

  if (els.card) els.card.classList.add('open');
  checkCompletion();
}

function toggleWriteup(qid) {
  const wu = document.querySelector(`.wu-ctn[data-wu="${qid}"]`);
  const btn = document.querySelector(`.feedback[data-feedback="${qid}"] .writeup-toggle`);
  if (!wu) return;
  const isShown = wu.classList.toggle('show');
  if (btn) {
    btn.textContent = isShown ? 'Hide Investigation Writeup ▴' : 'Show Investigation Writeup ▾';
    btn.classList.toggle('showed', isShown);
  }
}

function updateScore() {
  const correct = Object.values(state.answers).filter(a => a && a.correct).length;
  const total = QUESTIONS.length;
  const pct = (correct / total) * 100;
  document.getElementById('scoreNum').textContent = correct;
  document.getElementById('progFill').style.width = pct + '%';
}

function checkCompletion() {

  const done = QUESTIONS.every(q => {
    const a = state.answers[q.id];
    return a && (a.correct || a.locked);
  });
  if (done) {
    setTimeout(showCompletionModal, 600);
  }
}

function showCompletionModal() {
  const correct = Object.values(state.answers).filter(a => a && a.correct).length;
  const modal = document.getElementById('modal');
  const scoreEl = document.getElementById('modalScore');
  const verdictEl = document.getElementById('modalVerdict');
  scoreEl.textContent = correct + ' / ' + QUESTIONS.length;

  let cls = 'learning', msg = '';
  if (correct === 20)      { cls = 'perfect';   msg = 'PERFECT — FLAWLESS VICTORY'; }
  else if (correct >= 16)  { cls = 'excellent'; msg = 'EXCELLENT — ELITE PERFORMANCE'; }
  else if (correct >= 12)  { cls = 'good';      msg = 'GOOD — SOLID WORK'; }
  else                     { cls = 'learning';  msg = 'KEEP LEARNING — REVIEW THE WRITEUPS'; }
  verdictEl.className = 'verdict ' + cls;
  verdictEl.textContent = msg;
  modal.classList.add('show');
}

function reviewAnswers() {
  document.getElementById('modal').classList.remove('show');
  expandAll();

  const target = QUESTIONS.find(q => {
    const a = state.answers[q.id];
    return !a || (!a.correct && !a.locked);
  });
  if (target) {
    const el = document.getElementById('q' + target.id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function restartChallenge() {
  document.getElementById('modal').classList.remove('show');
  resetAll();
}

function resetAll() {
  if (!confirm('Reset all progress? This will clear every answer and lock the challenge again.')) return;
  clearState();

  location.reload();
}

function showChallenge() {
  document.getElementById('scorebar').style.display = 'flex';
  document.getElementById('main').style.display = 'block';
  renderTOC();
  renderCards();

  Object.keys(state.answers).forEach(qidStr => {
    const qid = parseInt(qidStr, 10);
    const a = state.answers[qidStr];
    if (!a) return;
    const els = getCardEls(qid);
    if (!els.input || !els.btn || !els.fb || !els.card || !els.status) return;
    const q = QUESTIONS.find(x => x.id === qid);
    if (!q) return;

    setAttemptsUI(qid, a.attempts || 0, !!a.locked);

    if (a.correct) {
      els.input.disabled = true;
      els.input.value = a.user;
      els.input.classList.add('correct');
      els.btn.disabled = true;
      els.card.classList.add('correct');
      els.status.textContent = '✓';
      els.status.style.color = '#00ff88';
      els.fb.className = 'feedback correct show';
      els.fb.innerHTML = buildCorrectFeedback(qid, q);
    } else if (a.locked) {
      els.input.disabled = true;
      els.input.value = a.user;
      els.input.classList.add('wrong');
      els.btn.disabled = true;
      els.card.classList.add('wrong');
      els.status.textContent = '✗';
      els.status.style.color = '#ff6b6b';
      els.fb.className = 'feedback wrong show';
      els.fb.innerHTML = buildWrongLockedFeedback(qid, q, a);
    } else {

      els.input.disabled = false;
      els.input.value = '';
      els.btn.disabled = false;
      els.card.classList.add('wrong');
      els.status.textContent = '✗';
      els.status.style.color = '#ff6b6b';
      els.fb.className = 'feedback wrong show';
      els.fb.innerHTML = buildWrongRetryFeedback(qid, q, a);
    }
  });
  updateScore();
}

loadState();
if (state.unlocked) {
  gate.style.display = 'none';
  showChallenge();
} else {
  gateInput.focus();
}
