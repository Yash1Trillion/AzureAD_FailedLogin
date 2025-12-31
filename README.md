# Azure AD Failed Login Analysis & MITRE ATT&CK Mapping

## Overview
This project simulates a **Security Operations Center (SOC)** workflow by analyzing failed login attempts in Azure Active Directory (Azure AD).  
It identifies potential credential-based attacks, maps them to **MITRE ATT&CK techniques**, and visualizes trends for actionable insights.

The project is designed for **defensive cybersecurity professionals** to demonstrate skills in:

- Cloud security (Azure AD, Azure Sentinel)
- Security analytics
- Data visualization
- MITRE ATT&CK framework mapping
- Python scripting for security automation

---

## Features

- Detect and aggregate **failed login attempts** per user and location.  
- Identify **anomalies** using simple threshold-based analysis.  
- Map suspicious activity to **MITRE ATT&CK techniques**, e.g., brute force, credential stuffing.  
- Generate **professional visualizations** (bar charts, trend analysis) for reporting.  
- Ready for extension to **AI-based anomaly detection**.

---

## Tech Stack

| Component            | Technology/Library                          |
|----------------------|--------------------------------------------|
| Cloud / Logs         | Azure AD, Azure Sentinel                     |
| Scripting / Analysis | Python 3.x, Pandas                           |
| Visualization        | Plotly, Kaleido                              |
| Version Control      | Git, GitHub                                  |
| Deployment / Sharing | GitHub Repository                            |

---

## Installation & Setup

1. **Clone the repository**

```bash
git clone https://github.com/Yash1Trillion/AzureAD_FailedLogin.git
cd AzureAD_FailedLogin
