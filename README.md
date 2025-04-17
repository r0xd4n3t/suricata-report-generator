<a id="top"></a>

<h1 align="center">🛡️ Suricata Report Generator</h1>

<p align="center"> 
  <kbd>
    <img src="https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/logo.png" alt="Logo" />
  </kbd>
</p>

<p align="center">
  <img src="https://img.shields.io/github/last-commit/r0xd4n3t/suricata-report-generator?style=flat" alt="Last Commit">
  <img src="https://img.shields.io/github/stars/r0xd4n3t/suricata-report-generator?color=brightgreen" alt="Stars">
  <img src="https://img.shields.io/github/forks/r0xd4n3t/suricata-report-generator?color=brightgreen" alt="Forks">
</p>

---

## 📜 Introduction

**Suricata Report Generator** provides a streamlined and professional approach to analyzing Suricata logs. Designed specifically for cybersecurity professionals and analysts, this script parses JSON logs from Suricata — a powerful open-source Network Intrusion Detection and Prevention System (NIDS/NIPS) — and generates a comprehensive, interactive HTML report.

Key features include:

- 📥 Reading and parsing Suricata JSON logs
- 📊 Visualizing data via bar and pie charts
- 🧮 Tabulating Top 10 Source IPs and Alert Messages
- 🧠 Mapping Unique IPs per Alert Message
- 💾 Outputting a complete, formatted HTML report

This tool empowers professionals to quickly assess network threats and identify critical indicators of compromise (IOCs).

---

## 📈 Sample Output

> 📋 Summary  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/sum.png)

> 📊 Top 10 Source IPs (Bar Chart)  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/1.png)

> 🥧 Top 10 Alert Messages (Pie Chart)  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/2.png)

> 🧾 Top 10 Source IPs (Table)  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/3.png)

> 🔔 Top 10 Alert Messages (Table)  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/4.png)

> 🔍 Unique IPs per Alert Message  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/5.png)

> 📚 Events Table  
> ![](https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/6.png)

---

## 🕹️ Usage

To execute the script, save it as `suricata_report_generator.py`, ensure the required libraries are installed, and run the script from your terminal:

```bash
python suricata_report_generator.py
```

#### 📁 The script expects a file named `eve.json` (Suricata's JSON output) in the same directory.
#### 📄 The output will be saved as `report.html`.

## 📝 Prerequisites

* <b>Python 3.x</b>
<p>Download from python.org</p>

* <b>Required Python Libraries:</b>
<p>Install using pip:</p>

```bash
pip install pandas plotly tqdm
```
* <b>Suricata JSON Logs:</b>b
<p>Ensure your `eve.json` log file is available in the working directory.</p>

## 🔍 Summary

<p>This script simplifies the complex task of interpreting Suricata alerts. With powerful visuals and structured tables, it gives security teams clear insights to support incident response and threat hunting efforts.</p>

<p align="center"><a href="#top">🔝 Back to Top</a></p>
