<a id="top"></a>

#

<h1 align="center">
Suricata Report Generator
</h1>

<p align="center"> 
  <kbd>
<img src="https://raw.githubusercontent.com/r0xd4n3t/suricata-report-generator/main/img/logo.png"></img>
  </kbd>
</p>

<p align="center">
<img src="https://img.shields.io/github/last-commit/r0xd4n3t/suricata-report-generator?style=flat">
<img src="https://img.shields.io/github/stars/r0xd4n3t/suricata-report-generator?color=brightgreen">
<img src="https://img.shields.io/github/forks/r0xd4n3t/suricata-report-generator?color=brightgreen">
</p>

# 📜 Introduction
This script provides a powerful tool for analyzing and visualizing Suricata events, a widely-used open-source Network Intrusion Detection and Prevention System (NIDS/NIPS).
The script reads event data from a JSON file, filters out specific unwanted messages, creates a bar chart of the top 10 source IP addresses, and generates an HTML report presenting the event data and the visualization.

This report can be a valuable resource for security professionals looking to gain insights into network traffic patterns and identify potential security threats.

## 🕹️ Usage
To run the script, save it to a Python file (e.g., suricata_report_generator.py) and execute it in a terminal or command prompt with Python.

The script will read event data from the 'eve.json' file, generate the report, and save it as 'report.html' in the same directory.

```
python suricata_report_generator.py
```

## 📝 Prerequisites
Python 3.x: The script is written in Python 3 and requires a compatible interpreter to run.
Download and install Python 3.x from https://www.python.org/downloads/.

Required Libraries: The script uses the following external libraries, which must be installed:

-   pandas
-   plotly
-   tqdm

To install these libraries, run the following command:

```
 pip install pandas plotly tqdm
```

Suricata JSON Output: The script expects input in the form of Suricata's JSON output format.
Ensure that the 'eve.json' file is available in the same directory as the script, or modify the script to read from a different file path.

After completing these prerequisites, the script is ready to be executed. 
The generated HTML report provides an overview of Suricata events, enabling security professionals to analyze network traffic, detect anomalies, and respond to potential threats.

<p align="center"><a href=#top>Back to Top</a></p>
