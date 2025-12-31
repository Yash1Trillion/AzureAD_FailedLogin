# Filename: project1_failed_signins_mitre.py

import pandas as pd
import plotly.express as px

# ==============================
# Step 1: Load CSV
# ==============================
csv_file = "FailedSignIns.csv"  # replace with your CSV filename
df = pd.read_csv(csv_file)

# ==============================
# Step 2: Convert time columns to datetime
# ==============================
df['First activity'] = pd.to_datetime(df['First activity'])
df['Last activity'] = pd.to_datetime(df['Last activity'])

# ==============================
# Step 3: Aggregate data
# ==============================

# Count alerts per Alert name
alert_summary = df.groupby('Alert name').size().reset_index(name='Count')

# Count alerts per Severity
severity_summary = df.groupby('Severity').size().reset_index(name='Count')

# ==============================
# Step 4: Bar chart - Alert counts
# ==============================
fig_alerts = px.bar(
    alert_summary,
    x='Alert name',
    y='Count',
    color='Count',
    text='Count',
    title='Failed Sign-ins Alerts Count',
    color_continuous_scale='Reds'
)
fig_alerts.update_layout(
    xaxis_title='Alert Name',
    yaxis_title='Number of Alerts',
    uniformtext_minsize=8,
    uniformtext_mode='hide',
    template='plotly_white'
)
fig_alerts.show()
fig_alerts.write_image("FailedSignIns_AlertsCount.png")

# ==============================
# Step 5: Bar chart - Severity distribution
# ==============================
fig_severity = px.bar(
    severity_summary,
    x='Severity',
    y='Count',
    color='Severity',
    text='Count',
    title='Failed Sign-ins Alerts by Severity',
    color_discrete_map={'High':'red','Medium':'orange','Low':'green'}
)
fig_severity.update_layout(
    xaxis_title='Severity',
    yaxis_title='Number of Alerts',
    uniformtext_minsize=8,
    uniformtext_mode='hide',
    template='plotly_white'
)
fig_severity.show()
fig_severity.write_image("FailedSignIns_Severity.png")

# ==============================
# Step 6: Timeline chart
# ==============================
timeline_summary = df.sort_values('First activity')
fig_timeline = px.timeline(
    timeline_summary,
    x_start='First activity',
    x_end='Last activity',
    y='Alert name',
    color='Severity',
    text='Severity',
    title='Failed Sign-ins Timeline'
)
fig_timeline.update_yaxes(autorange="reversed")
fig_timeline.update_layout(template='plotly_white')
fig_timeline.show()
fig_timeline.write_image("FailedSignIns_Timeline.png")

# ==============================
# Step 7: Highlight high-severity alerts
# ==============================
high_severity = df[df['Severity'] == 'High']
if not high_severity.empty:
    print("\nHigh Severity Alerts:")
    print(high_severity[['Alert name','First activity','Last activity','Severity']])

# ==============================
# Step 8: MITRE ATT&CK Mapping
# ==============================
def map_mitre(alert_name):
    """
    Map alerts to MITRE ATT&CK techniques for failed sign-ins
    """
    attack_map = []
    if "Failed Sign-in" in alert_name or "Sign-ins" in alert_name:
        attack_map.append("T1110 – Brute Force")
        attack_map.append("T1078.004 – Cloud Accounts")
    return attack_map

df['MITRE_Techniques'] = df['Alert name'].apply(map_mitre)

print("\nMITRE ATT&CK Mapping per Alert:")
for index, row in df.iterrows():
    print(f"Alert: {row['Alert name']}")
    print(f"Time: {row['First activity']} → {row['Last activity']}")
    print(f"Severity: {row['Severity']}")
    print(f"Mapped MITRE Techniques: {', '.join(row['MITRE_Techniques'])}")
    print("-"*60)

print("\nProject visualization and MITRE mapping complete. PNGs saved.")
