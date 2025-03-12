import requests
import os

def analyze_security(response):
    """
    Analyzes API security based on OWASP API Security Top 10 risks.
    """
    risks = []
    
    # Check for missing authentication headers
    if "Authorization" not in response.request.headers:
        risks.append("Missing Authentication")

    # Check for exposed sensitive data
    if "application/json" in response.headers.get("Content-Type", ""):
        risks.append("Potential Data Exposure")

    # Check for CORS misconfiguration
    if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
        risks.append("CORS Misconfiguration - Open to All Origins")

    return risks

def save_report(api_url, security_issues, status_code):
    """
    Saves the API security scan results into a markdown report.
    """
    # Ensure the reports directory exists
    os.makedirs("reports", exist_ok=True)

    report_filename = f"reports/{api_url.replace('https://', '').replace('/', '_')}.md"
    
    with open(report_filename, "w") as f:
        f.write(f"# API Security Report for {api_url}\n\n")
        f.write(f"## Scan Summary\n")
        f.write(f"- **Status Code:** {status_code}\n")
        f.write(f"- **Security Issues Found:** {', '.join(security_issues) if security_issues else 'None'}\n")
    
    print(f"[+] Report saved: {report_filename}")

def scan_api(api_url):
    """
    Scans the given API URL and analyzes security vulnerabilities.
    """
    try:
        response = requests.get(api_url)
        print(f"Scanning {api_url}...")

        security_issues = analyze_security(response)

        if security_issues:
            print(f"[!] Security Risks Detected: {', '.join(security_issues)}")
        else:
            print("[+] No obvious security issues found.")

        # Save report
        save_report(api_url, security_issues, response.status_code)

    except requests.exceptions.RequestException as e:
        print(f"[!] Error scanning {api_url}: {e}")

if __name__ == "__main__":
    target_api = input("Enter API URL to scan: ")
    scan_api(target_api)
