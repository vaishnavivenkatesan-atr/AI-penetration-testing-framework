from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
from reportlab.pdfgen import canvas
import socket
import time
import matplotlib.pyplot as plt
import os
import requests
from bs4 import BeautifulSoup
import pickle
import pandas as pd

app = Flask(__name__)

last_result = {}

# Load XGBoost model
with open("xgboost_risk_model.pkl", "rb") as file:
    xgb_model = pickle.load(file)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    global last_result

    start_time = time.time()

    target = request.form["target"]
    parsed = urlparse(target)

    open_ports = []

    status = "Invalid URL"
    risk = "unknown"
    score = 0
    grade = "C"

    recommendations = []
    server = "Unknown"
    title = "unknown"
    response_code = "unknown"
    https_status = "no"

    vulnerabilities = []
    security_headers = {}
    ai_prediction = "unknown"

    if parsed.scheme and parsed.hostname:

        status = "Valid URL"
        host = parsed.hostname

        ports = [22, 80, 443]

        # Port scanning
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)

                result = s.connect_ex((host, port))

                if result == 0:
                    open_ports.append(port)

                s.close()

            except:
                pass

        # -----------------------------
        # XGBoost Risk Prediction
        # -----------------------------

        open_count = len(open_ports)

        port_22_status = 1 if 22 in open_ports else 0
        port_80_status = 1 if 80 in open_ports else 0
        port_443_status = 1 if 443 in open_ports else 0

        features = pd.DataFrame([{
            "open_ports": open_count,
            "ports_22": port_22_status,
            "ports_80": port_80_status,
            "ports_443": port_443_status
        }])

        prediction = xgb_model.predict(features)[0]
        if prediction == 0:
            ai_prediction = "low risk"
        elif prediction == 1:
            ai_prediction = "medium risk"
        else:
            ai_prediction = "high risk"

        if prediction == 0:
            risk = "Low"
            score = 100

        elif prediction == 1:
            risk = "Medium"
            score = 80

        else:
            risk = "High"
            score = 60

        # Security Grade
        if score >= 90:
            grade = "A+"

        elif score >= 80:
            grade = "A"

        elif score >= 70:
            grade = "B"    

        elif score >= 60:
            grade = "C"

        else:
            grade = "D"

        # -----------------------------
        # Detect Server
        # -----------------------------

        if 443 in open_ports:
            server = "HTTPS Web Server"

        elif 80 in open_ports:
            server = "HTTP Web Server"

        elif 22 in open_ports:
            server = "SSH Server"

        else:
            server = "Unknown"

        # -----------------------------
        # Website Analysis
        # -----------------------------

        try:
            response = requests.get(target, timeout=5)

            response_code = response.status_code

            required_headers = {
                "Content-Security-Policy": "Helps prevent XSS attacks.",
                "X-Frame-Options": "Helps prevent clickjacking attacks.",
                "X-Content-Type-Options": "Prevents MIME-type sniffing.",
                "Strict-Transport-Security": "Forces browsers to use HTTPS.",
                "Referrer-Policy": "Controls referrer information.",
                "Permissions-Policy": "Controls access to browser features."
            }

            for header, description in required_headers.items():

                if header in response.headers:
                    security_headers[header] = "present"

                else:
                    security_headers[header] = "missing"

                    vulnerabilities.append({
                        "name": f"Missing {header}",
                        "severity": "medium",
                        "description": description
                    })

            soup = BeautifulSoup(response.text, "html.parser")

            if soup.title:
                title = soup.title.string.strip()
            else:
                title = "No title"

            if parsed.scheme == "https":
                https_status = "Yes ✅"
            else:
                https_status = "No ❌"

        except:
            title = "Unable to fetch"
            response_code = "error"
            https_status = "Unable to check"

        # -----------------------------
        # AI Security Recommendations
        # -----------------------------

        if 22 in open_ports:
            recommendations.append(
                "Close SSH port if not required."
            )

        if 80 in open_ports:
            recommendations.append(
                "Redirect HTTP traffic to HTTPS."
            )

        if 443 in open_ports:
            recommendations.append(
                "Use a valid SSL certificate."
            )

        recommendations.append("Enable Firewall.")
        recommendations.append("Keep software updated.")
        recommendations.append("Use strong passwords.")

        # -----------------------------
        # Port Scan Chart
        # -----------------------------

        closed_count = len(ports) - open_count

        plt.figure(figsize=(4, 4))

        plt.pie(
            [open_count, closed_count],
            labels=["Open", "Closed"],
            autopct="%1.1f%%",
            colors=["red", "green"],
            startangle=90
        )

        plt.title("Ports Scan Result")

        chart_path = os.path.join("static", "chart.png")

        plt.savefig(chart_path)
        plt.close()

    else:
        recommendations.append(
            "Please enter a valid URL."
        )

    # -----------------------------
    # Scan Time
    # -----------------------------

    scan_time = round(time.time() - start_time, 2)

    # -----------------------------
    # Store Result
    # -----------------------------

    last_result = {
        "target": target,
        "status": status,
        "ports": open_ports,
        "risk": risk,
        "score": score,
        "server": server,
        "scan_time": scan_time,
        "recommendations": recommendations,
        "title": title,
        "response_code": response_code,
        "https_status": https_status,
        "grade": grade,
        "vulnerabilities": vulnerabilities,
        "security_headers": security_headers,
        "ai_prediction": ai_prediction
    }

    return render_template(
        "result.html",
        target=target,
        status=status,
        ports=open_ports,
        risk=risk,
        server=server,
        recommendations=recommendations,
        score=score,
        scan_time=scan_time,
        title=title,
        response_code=response_code,
        https_status=https_status,
        grade=grade,
        vulnerabilities=vulnerabilities,
        security_headers=security_headers,
        ai_prediction=ai_prediction
    )


@app.route("/download")
def download():

    pdf = canvas.Canvas("Scan_Report.pdf")

    # -----------------------------
    # Title
    # -----------------------------

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawCentredString(
        300,
        800,
        "AI Penetration Testing Report"
    )

    y = 760

    # -----------------------------
    # Basic Scan Information
    # -----------------------------

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Scan Information")
    y -= 30

    pdf.setFont("Helvetica", 11)

    information = [
        f"Target URL : {last_result['target']}",
        f"Status : {last_result['status']}",
        f"Scan Time : {last_result['scan_time']} seconds",
        f"Detected Server : {last_result['server']}",
        f"Website Title : {last_result['title']}",
        f"HTTP Response Code : {last_result['response_code']}",
        f"HTTPS Status : Yes" if last_result["https_status"] == "Yes ✅" else f"HTTPS Status : No"
    ]

    for item in information:
        pdf.drawString(60, y, item)
        y -= 22

    # -----------------------------
    # Security Assessment
    # -----------------------------

    y -= 10

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Security Assessment")
    y -= 30

    pdf.setFont("Helvetica", 11)

    open_ports = last_result["ports"]

    if open_ports:
        ports_text = ", ".join(map(str, open_ports))
    else:
        ports_text = "None"

    assessment = [
        f"Open Ports : {ports_text}",
        f"Security Score : {last_result['score']}/100",
        f"Security Grade : {last_result['grade']}",
        f"AI Risk Prediction : {last_result['ai_prediction']}"
    ]

    for item in assessment:
        pdf.drawString(60, y, item)
        y -= 22

    # -----------------------------
    # Security Headers
    # -----------------------------

    y -= 10

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Security Headers")
    y -= 25

    pdf.setFont("Helvetica", 10)

    for header, status in last_result["security_headers"].items():

        pdf.drawString(
            60,
            y,
            f"{header} : {status}"
        )

        y -= 18

        # New page if required
        if y < 80:
            pdf.showPage()
            y = 800
            pdf.setFont("Helvetica", 10)

    # -----------------------------
    # Vulnerabilities
    # -----------------------------

    y -= 10

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Vulnerabilities Detected")
    y -= 25

    pdf.setFont("Helvetica", 10)

    if last_result["vulnerabilities"]:

        for vulnerability in last_result["vulnerabilities"]:

            pdf.drawString(
                60,
                y,
                f"{vulnerability['name']} - Severity: {vulnerability['severity']}"
            )

            y -= 18

            pdf.drawString(
                70,
                y,
                vulnerability["description"]
            )

            y -= 25

            if y < 80:
                pdf.showPage()
                y = 800
                pdf.setFont("Helvetica", 10)

    else:

        pdf.drawString(
            60,
            y,
            "No vulnerabilities detected."
        )

        y -= 20

    # -----------------------------
    # AI Recommendations
    # -----------------------------

    y -= 10

    if y < 120:
        pdf.showPage()
        y = 800

    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "AI Security Recommendations")
    y -= 25

    pdf.setFont("Helvetica", 10)

    for item in last_result["recommendations"]:

        pdf.drawString(
            60,
            y,
            "- " + item
        )

        y -= 20

        if y < 80:
            pdf.showPage()
            y = 800
            pdf.setFont("Helvetica", 10)

    # -----------------------------
    # Finish PDF
    # -----------------------------

    pdf.save()

    return send_file(
        "Scan_Report.pdf",
        as_attachment=True
    )
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
