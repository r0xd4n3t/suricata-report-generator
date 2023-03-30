import json
import pandas as pd
import plotly.express as px
from tqdm import tqdm
from datetime import datetime

def read_events(file_path):
    try:
        with open(file_path) as f:
            events = [json.loads(line) for line in f]
        return events
    except Exception as e:
        print(f"[!] Error reading events: {e}")
        return []

def create_bar_chart(data_frame):
    top_src_ips = data_frame['src_ip'].value_counts().head(10)
    fig = px.bar(
        top_src_ips,
        x=top_src_ips.index,
        y=top_src_ips.values,
        labels={'x': 'Source IP', 'y': 'Count'}
    )
    return fig

def create_html_report(fig, events, top_src_ips):
    excluded_messages = {
        "ET SCAN Malformed Packet SYN RST",
        "SURICATA Applayer Detect protocol only one direction",
        "SURICATA Applayer Mismatch protocol both directions",
        "SURICATA Applayer Wrong direction first Data",
        "SURICATA HTTP unable to match response to request",
        "SURICATA IPv4 invalid checksum",
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
        "SURICATA STREAM Packet with broken ack",
        "SURICATA STREAM Packet with invalid ack",
        "SURICATA STREAM Packet with invalid timestamp",
        "SURICATA STREAM reassembly sequence GAP -- missing packet(s)",
        "SURICATA STREAM RST recv but no session",
        "SURICATA STREAM SHUTDOWN RST invalid ack",
        "SURICATA STREAM SYN resend",
        "SURICATA STREAM TIMEWAIT invalid ack",
        "SURICATA TCPv4 invalid checksum",
        "SURICATA TLS invalid certificate",
        "SURICATA TLS invalid handshake message",
        "SURICATA TLS invalid record/traffic",
        "SURICATA TLS invalid record type"
    }

    table_rows = ''.join(
        f"<tr><td>{datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%Y-%m-%d')}</td>"
        f"<td>{datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%H:%M:%S')}</td>"
        f"<td>{e.get('src_ip', 'N/A')}</td>"
        f"<td>{e.get('dest_ip', 'N/A')}</td>"
        f"<td>{e['alert']['signature']}</td></tr>"
        for e in tqdm(events, desc="[*] Generating report")  # Add progress bar using tqdm
        if 'alert' in e and 'signature' in e['alert'] and e['alert']['signature'] not in excluded_messages
    )

    # Generate top 10 IPs table rows
    top_ips_table_rows = ''.join(
        f"<tr><td>{index}</td><td>{ip}</td><td>{count}</td></tr>"
        for index, (ip, count) in enumerate(top_src_ips.items(), start=1)
    )

    report = f'''
    <html>
    <head>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            table {{
                border-collapse: collapse;
                width: 100%;
            }}
            th, td {{
                border: 1px solid #dddddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .auto-fit {{
                width: auto;
            }}
        </style>
    </head>
    <body>
        <h1>Suricata Report</h1>
        <div>
            {fig.to_html(include_plotlyjs='cdn', full_html=False)}
        </div>
        <div>
            <h2>Top 10 Source IPs</h2>
            <table class="auto-fit">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>IP Address</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {top_ips_table_rows}
                </tbody>
            </table>
        </div>
        <div>
            <h2>Events</h2>
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Alert Message</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    '''

    return report

def write_report_to_file(report, file_path):
    try:
        with open(file_path, 'w') as f:
            f.write(report)
    except Exception as e:
        print(f"[!] Error writing report to file: {e}")

def main():
    events = read_events('eve.json')
    if not events:
        print("[!] No events found. Exiting.")
        return

    df = pd.json_normalize(events)
    top_src_ips = df['src_ip'].value_counts().head(10)
    fig = create_bar_chart(df)
    
    report = create_html_report(fig, events, top_src_ips)
    write_report_to_file(report, 'report.html')
    print("[+] Report generated successfully.")

if __name__ == '__main__':
    print("[*] Please wait...")
    main()
