import json
import pandas as pd
import plotly.express as px
from tqdm import tqdm
from datetime import datetime
from collections import Counter

minified_css = "body{font-family:'Nunito',sans-serif;background-color:#f8f9fa}h1,h2{font-weight:600;margin-bottom:20px}.container{max-width:1200px;margin:0 auto;padding:20px}"

excluded_messages = {
    "ET DNS Standard query response, Name Error",
    "ET SCAN Malformed Packet SYN RST",
    "GPL ICMP_INFO Echo Reply",
    "SURICATA Applayer Detect protocol only one direction",
    "SURICATA Applayer Mismatch protocol both directions",
    "SURICATA Applayer Wrong direction first Data",
    "SURICATA HTTP unable to match response to request",
    "SURICATA IPv4 invalid checksum",
    "SURICATA IPv4 padding required",
    "SURICATA IPv4 padding required ",
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
    "SURICATA TLS invalid record type",
    "SURICATA zero length padN option"
}

def read_events(file_path):
    try:
        with open(file_path) as f:
            events = [json.loads(line) for line in f]
            events.sort(key=lambda e: e['timestamp'])
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

def create_pie_chart(data_frame):
    # Filter out the excluded messages
    filtered_df = data_frame[data_frame.apply(lambda row: row['alert.signature'] not in excluded_messages, axis=1)]

    # Get the counts for each alert message and take only the top 10
    top_10_alert_counts = filtered_df['alert.signature'].value_counts().head(10)

    # Create the pie chart
    fig = px.pie(
        top_10_alert_counts,
        values=top_10_alert_counts.values,
        names=top_10_alert_counts.index,
        title='Top 10 Alert Messages Distribution',
        labels={'alert.signature': 'Alert Message'}
    )

    return fig

def create_html_report(bar_chart_fig, pie_chart_fig, filtered_events, top_src_ips, unique_ip_alerts):

    table_rows = ''.join(
        f"<tr><td>{datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%Y-%m-%d')}</td>"
        f"<td>{datetime.strptime(e['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%H:%M:%S')}</td>"
        f"<td>{e.get('src_ip', 'N/A')}</td>"
        f"<td>{e.get('dest_ip', 'N/A')}</td>"
        f"<td>{e['alert']['signature']}</td></tr>"
        for e in tqdm(filtered_events, desc="[*] Generating report")
        if 'alert' in e and 'signature' in e['alert'] and e['alert']['signature'].strip() not in excluded_messages
    )

    # Generate top 10 IPs table rows
    top_ips_table_rows = ''.join(
        f"<tr><td>{index}</td><td>{ip}</td><td>{count}</td></tr>"
        for index, (ip, count) in enumerate(top_src_ips.items(), start=1)
    )

    # Generate top 10 Alert Messages table rows
    alert_signatures = [e['alert']['signature'] for e in filtered_events if 'alert' in e and 'signature' in e['alert'] and e['alert']['signature'] not in excluded_messages]
    top_alert_counts = dict(Counter(alert_signatures).most_common(10))
    top_alert_counts_table_rows = ''.join(
    f"<tr><td>{index}</td><td>{alert_msg}</td><td>{count}</td></tr>"
    for index, (alert_msg, count) in enumerate(top_alert_counts.items(), start=1)
    )

    # Generate unique IP per Alert Message table rows
    unique_ip_alerts_sorted = sorted(unique_ip_alerts, key=lambda x: len(x[1]), reverse=True)
    unique_ip_alerts_table_rows = ''.join(
    f"<tr><td>{index}</td><td>{alert_msg}</td><td>{', '.join(ips)}</td><td>{len(ips)}</td></tr>"
    for index, (alert_msg, ips) in enumerate(unique_ip_alerts_sorted, start=1)
    if alert_msg not in excluded_messages
    )

    report = f'''
    <!DOCTYPE html>
    <html lang="en">
       <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Suricata Report</title>
          <link rel="icon" href="favicon.ico">
          <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/css/bootstrap.min.css" crossorigin="anonymous">
          <style>
            {minified_css}
          </style>
       </head>
       <body>
          <div class="container">
             <h1>Suricata Report</h1>
             <div class="row">
                <div class="col-md-12">
                   {bar_chart_fig.to_html(include_plotlyjs='cdn', full_html=False)}
                   {pie_chart_fig.to_html(include_plotlyjs='cdn', full_html=False)}
                </div>
             </div>
             <div class="row mt-4">
                <div class="col-md-12">
                   <h2>Top 10 Source IPs</h2>
                   <table class="table table-striped">
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
             </div>
         <div class="row mt-4">
            <div class="col-md-12">
               <h2>Top 10 Alert Messages</h2>
               <table class="table table-striped">
                  <thead>
                     <tr>
                        <th>Rank</th>
                        <th>Alert Message</th>
                        <th>Count</th>
                     </tr>
                  </thead>
                  <tbody>
                     {top_alert_counts_table_rows}
                  </tbody>
               </table>
            </div>
         </div>
             <div class="row mt-4">
                <div class="col-md-12">
                   <h2>Unique IPs per Alert Message</h2>
                   <table class="table table-striped">
                      <thead>
                         <tr>
                            <th>Number</th>
                            <th>Alert Message</th>
                            <th>IP Addresses</th>
                            <th>IP Count</th>
                         </tr>
                      </thead>
                      <tbody>
                         {unique_ip_alerts_table_rows}
                      </tbody>
                   </table>
                </div>
             </div>
             <div class="row mt-4">
                <div class="col-md-12">
                   <h2>Events</h2>
                   <table class="table table-striped">
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
             </div>
          </div>
          <script src="https://code.jquery.com/jquery-3.6.0.min.js" crossorigin="anonymous"></script>
          <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.min.js" crossorigin="anonymous"></script>
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

    # Filter out excluded messages
    filtered_df = df[df.apply(lambda row: row['alert.signature'] not in excluded_messages, axis=1)]

    # Get top_src_ips from filtered_df
    top_src_ips = filtered_df['src_ip'].value_counts().head(10)
    bar_chart_fig = create_bar_chart(filtered_df)
    pie_chart_fig = create_pie_chart(filtered_df)

    # Group by alert message and aggregate unique IP addresses
    unique_ip_alerts = filtered_df[filtered_df['alert.signature'].notnull()].groupby('alert.signature').agg({'src_ip': pd.Series.unique}).reset_index()
    unique_ip_alerts = [(alert_msg, ips) for alert_msg, ips in unique_ip_alerts.values if alert_msg not in excluded_messages]

    # Filter events based on filtered_df
    filtered_events = [e for e in events if e.get('alert', {}).get('signature') not in excluded_messages]

    report = create_html_report(bar_chart_fig, pie_chart_fig, filtered_events, top_src_ips, unique_ip_alerts)
    write_report_to_file(report, 'report.html')
    print("[+] Report generated successfully.")

if __name__ == '__main__':
    print("[*] Please wait...")
    main()
