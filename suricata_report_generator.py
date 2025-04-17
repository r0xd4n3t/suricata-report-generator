import json
from datetime import datetime, timezone, timedelta
from collections import Counter
from tqdm import tqdm
import logging

import pandas as pd
import plotly.express as px

gmt_8 = timezone(timedelta(hours=8))

# Constants and Configuration
MINIFIED_CSS = "body{font-family:'Nunito',sans-serif;background-color:#f8f9fa}h1,h2{font-weight:600;margin-bottom:20px}.container{max-width:1200px;margin:0 auto;padding:20px}"
EXCLUDED_MESSAGES = {
    "ET DNS Standard query response, Name Error",
    "ET EXPLOIT Possible CVE-2020-11899 Multicast out-of-bound read",
    "ET INFO TLS Handshake Failure",
    "ET SCAN Malformed Packet SYN RST",
    "GPL DNS SPOOF query response with TTL of 1 min. and no authority",
    "GPL ICMP_INFO Destination Unreachable Fragmentation Needed and DF bit was set",
    "GPL ICMP_INFO Destination Unreachable Network Unreachable",
    "GPL ICMP_INFO Destination Unreachable Port Unreachable",
    "GPL ICMP_INFO Echo Reply",
    "SURICATA Applayer Detect protocol only one direction",
    "SURICATA Applayer Mismatch protocol both directions",
    "SURICATA Applayer Wrong direction first Data",
    "SURICATA FRAG IPv4 Fragmentation overlap",
    "SURICATA GRE v0 flags",
    "SURICATA HTTP unable to match response to request",
    "SURICATA IPv4 invalid checksum",
    "SURICATA IPv4 padding required ",
    "SURICATA IPv4 padding required",
    "SURICATA SMTP data command rejected",
    "SURICATA SMTP invalid pipelined sequence",
    "SURICATA SMTP invalid reply",
    "SURICATA SMTP Mime encoded line len exceeded",
    "SURICATA STREAM 3way handshake excessive different SYN/ACKs",
    "SURICATA STREAM 3way handshake SYNACK with wrong ack",
    "SURICATA STREAM 3way handshake wrong seq wrong ack",
    "SURICATA STREAM bad window update",
    "SURICATA STREAM CLOSEWAIT FIN out of window",
    "SURICATA STREAM ESTABLISHED invalid ack",
    "SURICATA STREAM ESTABLISHED packet out of window",
    "SURICATA STREAM ESTABLISHED SYNACK resend with different seq",
    "SURICATA STREAM ESTABLISHED SYN resend",
    "SURICATA STREAM excessive retransmissions",
    "SURICATA STREAM FIN1 FIN with wrong seq",
    "SURICATA STREAM FIN1 invalid ack",
    "SURICATA STREAM FIN invalid ack",
    "SURICATA STREAM FIN out of window",
    "SURICATA STREAM FIN recv but no session",
    "SURICATA STREAM Last ACK with wrong seq",
    "SURICATA STREAM Packet with broken ack",
    "SURICATA STREAM Packet with invalid ack",
    "SURICATA STREAM Packet with invalid timestamp",
    "SURICATA STREAM reassembly overlap with different data",
    "SURICATA STREAM reassembly sequence GAP -- missing packet(s)",
    "SURICATA STREAM RST recv but no session",
    "SURICATA STREAM SHUTDOWN RST invalid ack",
    "SURICATA STREAM SYN resend",
    "SURICATA STREAM TIMEWAIT invalid ack",
    "SURICATA TCPv4 invalid checksum",
    "SURICATA TLS invalid certificate",
    "SURICATA TLS invalid handshake message",
    "SURICATA TLS invalid record/traffic",
    "SURICATA TLS invalid record type",
    "SURICATA UDPv4 invalid checksum",
    "SURICATA UDPv6 invalid checksum",
    "SURICATA zero length padN option"
}

# Logging Configuration
logging.basicConfig(filename='suricata_report.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s', datefmt='%I:%M %p %d/%m/%Y')


def read_events(file_path):
    """Read events from JSON file."""
    try:
        with open(file_path) as f:
            events = [json.loads(line) for line in f]
            events.sort(key=lambda e: e['timestamp'])
        return events
    except Exception as e:
        logging.error(f"Error reading events: {e}")
        return []


def filter_events(events):
    """Filter events to exclude specific messages."""
    return [
        e for e in events
        if 'alert' in e and 'signature' in e['alert'] and e['alert']['signature'].strip() not in EXCLUDED_MESSAGES
    ]


def calculate_summary(filtered_events):
    """Calculate summary statistics."""
    start_datetime = end_datetime = None
    total_alerts = 0

    for e in filtered_events:
        timestamp = datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
        timestamp_gmt8 = timestamp.astimezone(gmt_8)

        if not start_datetime or timestamp_gmt8 < start_datetime:
            start_datetime = timestamp_gmt8
        if not end_datetime or timestamp_gmt8 > end_datetime:
            end_datetime = timestamp_gmt8

        total_alerts += 1

    start_date, end_date = start_datetime.date(), end_datetime.date()
    start_time = start_datetime.strftime('%H:%M:%S')
    end_time = end_datetime.strftime('%H:%M:%S')

    total_time = end_datetime - start_datetime
    total_seconds = total_time.total_seconds()
    
    weeks = int(total_seconds // 604800)
    days = int((total_seconds % 604800) // 86400)
    hours = int((total_seconds % 86400) // 3600)
    minutes = int((total_seconds % 3600) // 60)
    seconds = int(total_seconds % 60)
    
    if weeks > 0:
        total_time_str = f"{weeks} weeks, {days} days, {hours} hours, {minutes} minutes, {seconds} seconds"
    elif days > 0:
        total_time_str = f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds"
    elif hours > 0:
        total_time_str = f"{hours} hours, {minutes} minutes, {seconds} seconds"
    else:
        total_time_str = f"{minutes} minutes, {seconds} seconds"

    return start_date, end_date, start_time, end_time, total_time_str, total_alerts


def create_bar_chart(data_frame):
    """Create a bar chart."""
    top_src_ips = data_frame['src_ip'].value_counts().head(10)
    fig = px.bar(
        top_src_ips,
        x=top_src_ips.index,
        y=top_src_ips.values,
        labels={'x': 'Source IP', 'y': 'Count'}
    )
    return fig


def create_pie_chart(data_frame):
    """Create a pie chart."""
    filtered_df = data_frame[data_frame['alert.signature'].apply(lambda msg: msg not in EXCLUDED_MESSAGES)]
    top_10_alert_counts = filtered_df['alert.signature'].value_counts().head(10)
    fig = px.pie(
        top_10_alert_counts,
        values=top_10_alert_counts.values,
        names=top_10_alert_counts.index,
        title='Top 10 Alert Messages Distribution',
        labels={'alert.signature': 'Alert Message'}
    )
    return fig


def format_event_row(e):
    timestamp = datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
    timestamp_gmt8 = timestamp.astimezone(gmt_8)
    return (
        f"<tr><td>{timestamp_gmt8.strftime('%Y-%m-%d')}</td>"
        f"<td>{timestamp_gmt8.strftime('%H:%M:%S')}</td>"
        f"<td>{e.get('src_ip', 'N/A')}</td>"
        f"<td>{e.get('dest_ip', 'N/A')}</td>"
        f"<td>{e['alert']['signature']}</td></tr>"
    )


def create_html_report(bar_chart_fig, pie_chart_fig, filtered_events, top_src_ips, unique_ip_alerts):
    """Enhanced HTML report with a dark mode toggle button."""

    table_rows = ''.join(
        format_event_row(e)
        for e in tqdm(filtered_events, desc="[*] Generating report")
        if 'alert' in e and 'signature' in e['alert'] and e['alert']['signature'].strip() not in EXCLUDED_MESSAGES
    )

    top_ips_table_rows = ''.join(
        f"<tr><td>{index}</td><td>{ip}</td><td>{count}</td></tr>"
        for index, (ip, count) in enumerate(top_src_ips.items(), start=1)
    )

    alert_signatures = [
        e['alert']['signature'] for e in filtered_events
        if 'alert' in e and 'signature' in e['alert'] and e['alert']['signature'] not in EXCLUDED_MESSAGES
    ]
    top_alert_counts = dict(Counter(alert_signatures).most_common(10))
    top_alert_counts_table_rows = ''.join(
        f"<tr><td>{index}</td><td>{alert_msg}</td><td>{count}</td></tr>"
        for index, (alert_msg, count) in enumerate(top_alert_counts.items(), start=1)
    )

    unique_ip_alerts_sorted = sorted(unique_ip_alerts, key=lambda x: len(x[1]), reverse=True)
    unique_ip_alerts_table_rows = ''.join(
        f"<tr><td>{index}</td><td>{alert_msg}</td><td>{', '.join(ips)}</td><td>{len(ips)}</td></tr>"
        for index, (alert_msg, ips) in enumerate(unique_ip_alerts_sorted, start=1)
        if alert_msg not in EXCLUDED_MESSAGES
    )

    start_date, end_date, start_time, end_time, total_time_str, total_alerts = calculate_summary(filtered_events)

    summary_table = f'''
    <table class="table table-hover table-bordered text-center shadow-sm">
        <thead class="table-primary">
            <tr>
                <th>Start Date</th>
                <th>End Date</th>
                <th>Start Time</th>
                <th>End Time</th>
                <th>Total Duration</th>
                <th>Total Alerts</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{start_date}</td>
                <td>{end_date}</td>
                <td>{start_time}</td>
                <td>{end_time}</td>
                <td>{total_time_str}</td>
                <td>{total_alerts}</td>
            </tr>
        </tbody>
    </table>
    '''

    enhanced_css = '''
    body.light-mode {
        font-family: 'Nunito', sans-serif;
        background: linear-gradient(135deg, #eceff1, #ffffff);
        color: #333;
    }
    body.dark-mode {
        font-family: 'Nunito', sans-serif;
        background-color: #121212;
        color: #ffffff;
    }
    h1, h2 {
        font-weight: 700;
        margin-bottom: 15px;
        color: #0d6efd;
        text-shadow: 1px 1px #ddd;
    }
    .card {
        box-shadow: 0 6px 12px rgba(0,0,0,.1);
        border-radius: 12px;
        margin-bottom: 30px;
    }
    .footer {
        text-align: center;
        background-color: #0d6efd;
        color: white;
        padding: 15px;
        position: fixed;
        bottom: 0;
        width: 100%;
        font-weight: 500;
    }
    '''

    theme_toggle_script = '''
    <script>
        function toggleTheme() {
            document.body.classList.toggle('dark-mode');
            document.body.classList.toggle('light-mode');
        }
        document.addEventListener('DOMContentLoaded', () => {
            document.body.classList.add('light-mode');
        });
    </script>
    '''

    report = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Suricata Security Alert Report</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>{enhanced_css}</style>
    </head>
    <body>
        <div class="container py-4">
            <button class="btn btn-secondary float-end" onclick="toggleTheme()">Toggle Dark Mode</button>
            <h1 class="text-center mb-4">📊 Suricata Security Alert Report</h1>
            <div class="card p-4">
                {summary_table}
                <div class="row mt-4">
                    <div class="col-md-12 mb-4">
                        {bar_chart_fig.to_html(include_plotlyjs='cdn', full_html=False)}
                    </div>
                    <div class="col-md-12">
                        {pie_chart_fig.to_html(include_plotlyjs='cdn', full_html=False)}
                    </div>
                </div>
            </div>

            <div class="card p-4">
                <h2>Top 10 Source IP Addresses</h2>
                <table class="table table-bordered table-striped table-hover text-center">
                    <thead class="table-secondary">
                        <tr><th>#</th><th>IP Address</th><th>Count</th></tr>
                    </thead>
                    <tbody>{top_ips_table_rows}</tbody>
                </table>
            </div>

            <div class="card p-4">
                <h2>Top 10 Alert Messages</h2>
                <table class="table table-bordered table-striped table-hover text-center">
                    <thead class="table-secondary">
                        <tr><th>#</th><th>Alert Message</th><th>Count</th></tr>
                    </thead>
                    <tbody>{top_alert_counts_table_rows}</tbody>
                </table>
            </div>

            <div class="card p-4">
                <h2>Unique IPs per Alert Message</h2>
                <table class="table table-bordered table-striped table-hover">
                    <thead class="table-secondary">
                        <tr><th>#</th><th>Alert Message</th><th>IP Addresses</th><th>IP Count</th></tr>
                    </thead>
                    <tbody>{unique_ip_alerts_table_rows}</tbody>
                </table>
            </div>

            <div class="card p-4">
                <h2>Detailed Event Log</h2>
                <table class="table table-bordered table-striped table-hover text-center">
                    <thead class="table-secondary">
                        <tr><th>Date</th><th>Time</th><th>Source IP</th><th>Destination IP</th><th>Alert Message</th></tr>
                    </thead>
                    <tbody>{table_rows}</tbody>
                </table>
            </div>
        </div>

        <footer class="footer">
            <div class="container">
                Suricata Report Generator © r0xd4n3t <script>document.write(new Date().getFullYear())</script>
            </div>
        </footer>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
        {theme_toggle_script}
    </body>
    </html>
    '''

    return report

def write_report_to_file(report, file_path):
    """Write report to file."""
    try:
        with open(file_path, 'w') as f:
            f.write(report)
        logging.info(f"Report written to {file_path}")
    except Exception as e:
        logging.error(f"Error writing report to file: {e}")


def main():
    """Main function."""
    input_file_path = 'eve.json'

    events = read_events(input_file_path)
    if not events:
        logging.warning("No events found. Exiting.")
        return

    df = pd.json_normalize(events)
    filtered_events = filter_events(events)
    filtered_df = df[df['alert.signature'].apply(lambda msg: msg not in EXCLUDED_MESSAGES)]

    top_src_ips = filtered_df['src_ip'].value_counts().head(10)
    bar_chart_fig = create_bar_chart(filtered_df)
    pie_chart_fig = create_pie_chart(filtered_df)

    unique_ip_alerts = filtered_df[filtered_df['alert.signature'].notna()].groupby('alert.signature')['src_ip'].unique().reset_index()
    unique_ip_alerts = [(alert_msg, ips) for alert_msg, ips in unique_ip_alerts.values if alert_msg not in EXCLUDED_MESSAGES]

    report = create_html_report(bar_chart_fig, pie_chart_fig, filtered_events, top_src_ips, unique_ip_alerts)
    output_file_path = 'report.html'
    write_report_to_file(report, output_file_path)
    logging.info("Report generated successfully.")


if __name__ == '__main__':
    current_time = datetime.now().strftime('%I:%M %p %d/%m/%Y')
    logging.info(f"Starting Suricata Report generation at {current_time}")
    main()
