# AI-penetration-testing-framework
AI based penetration testing framework using Python, Flask and XGBoost .

## 📌 Project Overview

This project combines penetration testing techniques with machine learning to analyze a target URL, identify open ports, detect web services, predict security risk, and generate a security report.

The framework provides a simple web-based interface using Flask where users can enter a target URL and start a security scan.

## 🚀 Features

- 🔍 Target URL validation
- 🌐 Port scanning
- 🔐 Open port detection
- 🖥️ Server/service detection
- 🤖 AI-based risk prediction using XGBoost
- 📊 Security score and risk level
- 📈 Visual security chart
- 💡 AI-based security recommendations
- 📄 Automated PDF security report

## 🛠️ Technologies Used

- Python
- Flask
- XGBoost
- HTML
- CSS
- Matplotlib
- ReportLab
- Socket
- Requests
- BeautifulSoup

## 🤖 Machine Learning

XGBoost is used to predict the security risk level based on the detected port information.

The model classifies the target into different risk levels such as:

- Low Risk
- Medium Risk
- High Risk

## 🔄 How It Works

```text
Enter Target URL
       ↓
Validate URL
       ↓
Scan Ports
       ↓
Detect Services
       ↓
AI Risk Prediction
       ↓
Generate Security Score
       ↓
Security Recommendations
       ↓
Generate PDF Report
