# Detection Rules

All six rules run as scheduled searches every 5 minutes over the previous 15 minutes. The same SPL is in [`/detections`](../detections) as standalone `.spl` files so each one can be pasted straight into Splunk's search bar.

---

## 1. SSH Brute Force

**MITRE ATT&CK:** T1110.001 Brute Force: Password Guessing
**Severity:** High

```spl
index=soc_lab sourcetype=linux_secure action=failure
| stats count AS failures dc(user) AS users_tried values(user) AS usernames BY src_ip
| where failures > 20
```

**Why it works:** an attacker guessing passwords produces a burst of failures from one address in a short time. A person who forgot their password might fail three or four times, not twenty.

**Possible false positives:** a misconfigured script or service with an old password stored in it. Check whether the source IP is internal and whether the username belongs to a service account.

**Triage:** is the IP internal or external? Did any attempt succeed (see rule 2)? Is the targeted account privileged?

---

## 2. Successful Login After Brute Force

**MITRE ATT&CK:** T1110 Brute Force, T1078 Valid Accounts
**Severity:** Critical

```spl
index=soc_lab sourcetype=linux_secure (action=failure OR action=success)
| stats count(eval(action="failure")) AS failures
        count(eval(action="success")) AS successes
        latest(eval(if(action="success",user,null()))) AS compromised_user BY src_ip
| where failures > 10 AND successes > 0
```

**Why it works:** many failures followed by a success from the same address usually means the attacker found the password. This is the alert that matters most, because the attacker now has a foothold.

**Possible false positives:** a genuine user who finally remembers their password. The failure count of over 10 makes this unlikely.

**Triage:** treat as a confirmed compromise until proven otherwise. Check what the account did after logging in (sudo commands, new processes, outbound connections).

---

## 3. Password Spraying

**MITRE ATT&CK:** T1110.003 Brute Force: Password Spraying
**Severity:** High

```spl
index=soc_lab sourcetype=linux_secure action=failure
| stats dc(user) AS distinct_users count AS attempts values(user) AS usernames BY src_ip
| where distinct_users >= 8
```

**Why it works:** spraying tries one or two common passwords against many accounts to stay under per-account lockout limits. Rule 1 can miss it because each account only sees one failure, so this rule counts distinct usernames instead.

**Possible false positives:** a vulnerability scanner run by your own team. Confirm with the asset owner and add the scanner IP to an allow list.

**Triage:** do the usernames exist on the host (`invalid user` in the log means they don't)? A list of default names such as `oracle`, `postgres` and `test` points to an automated tool.

---

## 4. Suspicious Sudo Command

**MITRE ATT&CK:** T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching
Related: T1003.008 /etc/passwd and /etc/shadow, T1105 Ingress Tool Transfer
**Severity:** High

```spl
index=soc_lab sourcetype=linux_secure action=sudo
| where match(sudo_command, "(?i)/etc/shadow|/etc/passwd|wget |curl |nc |chmod \+s")
| table _time host sudo_user sudo_command
```

**Why it works:** reading `/etc/shadow` gives an attacker password hashes to crack offline, and `wget` or `curl` run as root is a common way to pull down malware. Normal admin work on this server is package updates and service restarts.

**Possible false positives:** an admin legitimately downloading a package with `curl`. Check the destination URL and whether a change ticket exists.

---

## 5. Web Directory Scanning

**MITRE ATT&CK:** T1595.003 Active Scanning: Wordlist Scanning
**Severity:** Medium

```spl
index=soc_lab sourcetype=access_combined (status=404 OR status=403)
| stats count AS errors dc(uri_path) AS unique_paths values(useragent) AS user_agents BY clientip
| where errors >= 25 OR match(mvjoin(user_agents," "), "(?i)gobuster|dirbuster|nikto|ffuf|dirb")
```

**Why it works:** tools like gobuster request hundreds of guessed paths (`/admin`, `/.env`, `/.git/config`) and most return 404. A normal visitor follows links and rarely hits missing pages.

**Possible false positives:** a broken link on the site causing repeated 404s, or a search engine crawler. Check the user agent and the variety of paths.

**Triage:** did any of the probed paths return 200? A 200 on `/.env` or `/.git/config` means sensitive data may have leaked.

---

## 6. SQL Injection Attempt

**MITRE ATT&CK:** T1190 Exploit Public-Facing Application
**Severity:** High

```spl
index=soc_lab sourcetype=access_combined
| eval decoded=urldecode(uri)
| where match(decoded, "(?i)union\s+select|'\s*or\s*'1'\s*=\s*'1|sleep\(|drop\s+table|'--")
| table _time clientip status useragent decoded
```

**Why it works:** attackers URL-encode their payloads, so the rule decodes the URL first and then looks for common injection patterns.

**Possible false positives:** low. Legitimate URLs almost never contain `UNION SELECT`.

**Triage:** look at the HTTP status. A `500` means the payload reached the database and broke the query, which suggests the parameter is injectable and needs fixing urgently.

---

## Tuning notes

- Thresholds are set for a small lab server. A busy production server would need higher numbers, ideally based on a baseline of normal activity.
- Internal scanner IPs and service accounts should be excluded with a lookup table rather than hard-coded into each search.
- Rules 1, 2 and 4 together describe one attack chain. In a production SIEM they would be combined into a single correlated notable event.
