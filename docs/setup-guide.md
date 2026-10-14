# Setup Guide (macOS)

Tested with Splunk Enterprise on macOS using the free licence. Commands assume Splunk is installed in the default location, `/Applications/Splunk`.

## 1. Get the project

Keep the project in your home folder rather than Desktop or Documents. macOS privacy controls can stop Splunk reading files in those two folders.

```bash
cd ~
git clone https://github.com/VijayalaxmiKummari/home-soc-lab.git
cd home-soc-lab
```

## 2. Generate the logs

```bash
python3 log-generator/generate_logs.py
```

This creates `logs/auth.log` and `logs/access.log` with two hours of activity and the six attacks.

## 3. Install the Splunk app

```bash
cp -R splunk/soc_lab /Applications/Splunk/etc/apps/
mkdir -p /Applications/Splunk/etc/apps/soc_lab/local
sed "s#/CHANGE/ME#$HOME#" splunk/soc_lab/default/inputs.conf.example \
  > /Applications/Splunk/etc/apps/soc_lab/local/inputs.conf
cat /Applications/Splunk/etc/apps/soc_lab/local/inputs.conf
```

The last command should show two `[monitor://...]` lines pointing at your real `logs` folder.

## 4. Restart Splunk

```bash
/Applications/Splunk/bin/splunk restart
```

## 5. Check the data arrived

Open http://localhost:8000, go to **Search & Reporting**, set the time range to **Last 4 hours** and run:

```spl
index=soc_lab | stats count BY sourcetype
```

You should see `linux_secure` and `access_combined` with counts.

If nothing appears:
- Run `/Applications/Splunk/bin/splunk list monitor` and check both log files are listed.
- Check the paths in `local/inputs.conf` match where the project lives.

## 6. Run the detections

Open each file in the `detections/` folder, paste its contents into the search bar and run it over **Last 4 hours**. Each should return at least one result.

## 7. Open the dashboard

**Apps > Home SOC Lab > SOC Lab Overview** (or **Dashboards** in Search & Reporting).

## 8. See the alerts fire live

The scheduled alerts look at the last 15 minutes, so replay the attacks with current timestamps:

```bash
python3 log-generator/generate_logs.py --attack-now
```

Wait up to 5 minutes, then open **Activity > Triggered Alerts**.

## 9. Take screenshots for the README

Save these in the `screenshots/` folder (macOS: Cmd+Shift+4 to select an area):

| File name | What to capture |
|---|---|
| `dashboard.png` | The SOC Lab Overview dashboard |
| `brute-force-detection.png` | Results of the SSH brute force search |
| `sql-injection-detection.png` | Results of the SQL injection search |
| `triggered-alerts.png` | Activity > Triggered Alerts after step 8 |
| `incident-timeline.png` | The timeline search from the incident report |

## Resetting the lab

```bash
rm -rf logs
/Applications/Splunk/bin/splunk stop
/Applications/Splunk/bin/splunk clean eventdata -index soc_lab -f
/Applications/Splunk/bin/splunk start
python3 log-generator/generate_logs.py
```
