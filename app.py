import streamlit as st
import subprocess
import tempfile
import json
import os
import sys
import shutil
import uuid
import difflib
import csv
import io
import html
from datetime import datetime

try:
    import pandas as pd
except Exception:
    pd = None


st.set_page_config(
    page_title="AI-IAC Configuration Validation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


UNSAFE_TERRAFORM = '''resource "aws_security_group" "demo" {
  name        = "demo-security-group"
  description = "Security group for Checkov demonstration"

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Unrestricted outbound access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project     = "AI-IAC-Demo"
    Environment = "Demo"
  }
}
'''

SAFE_TERRAFORM = '''resource "aws_security_group" "safe_demo" {
  name        = "safe-demo-security-group"
  description = "Security group with restricted network access"

  ingress {
    description = "SSH access from trusted internal network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  egress {
    description = "HTTPS outbound to trusted internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  tags = {
    Project     = "AI-IAC-Demo"
    Environment = "Demo"
  }
}
'''


if "code" not in st.session_state:
    st.session_state.code = UNSAFE_TERRAFORM

if "filename" not in st.session_state:
    st.session_state.filename = "main.tf"

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "findings" not in st.session_state:
    st.session_state.findings = []

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None

if "ai_explanation" not in st.session_state:
    st.session_state.ai_explanation = ""

if "suggested_code" not in st.session_state:
    st.session_state.suggested_code = ""

if "before_code" not in st.session_state:
    st.session_state.before_code = ""

if "after_code" not in st.session_state:
    st.session_state.after_code = ""

if "cvs_history" not in st.session_state:
    st.session_state.cvs_history = []

if "baseline_code" not in st.session_state:
    st.session_state.baseline_code = ""

if "validation_gate" not in st.session_state:
    st.session_state.validation_gate = False

if "settings_check" not in st.session_state:
    st.session_state.settings_check = ""

if "settings_skip" not in st.session_state:
    st.session_state.settings_skip = ""

if "plan_result" not in st.session_state:
    st.session_state.plan_result = None

if "current_page" not in st.session_state:
    st.session_state.current_page = "🏠 Dashboard"


def add_audit(action, details=""):
    st.session_state.audit_log.insert(
        0,
        {
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Action": action,
            "Details": details
        }
    )


def set_code(value, filename="main.tf"):
    st.session_state.code = value
    st.session_state.filename = filename
    add_audit("Configuration loaded", filename)


def get_checkov_command(file_path):
    command = [
        sys.executable,
        "-m",
        "checkov",
        "-f",
        file_path,
        "--framework",
        "terraform",
        "--output",
        "json"
    ]

    if st.session_state.settings_check.strip():
        command.extend(["--check", st.session_state.settings_check.strip()])

    if st.session_state.settings_skip.strip():
        command.extend(["--skip", st.session_state.settings_skip.strip()])

    return command


def extract_json(text):
    text = text.strip()

    if not text:
        return None

    try:
        return json.loads(text)
    except Exception:
        pass

    starts = [i for i, char in enumerate(text) if char in "[{"]

    for start in starts:
        candidate = text[start:]

        try:
            return json.loads(candidate)
        except Exception:
            continue

    return None


def safe_value(value):
    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    return str(value)


def get_line_number(check):
    value = check.get("file_line_range")

    if isinstance(value, list) and value:
        return value[0]

    value = check.get("file_line_range")

    if isinstance(value, int):
        return value

    return check.get("line", "")


def parse_checkov_results(data):
    results = []

    if not isinstance(data, dict):
        return results

    failed = data.get("results", {}).get("failed_checks", [])
    passed = data.get("results", {}).get("passed_checks", [])
    skipped = data.get("results", {}).get("skipped_checks", [])

    for item in failed:
        results.append(
            {
                "Check ID": safe_value(item.get("check_id")),
                "Check": safe_value(item.get("check_name")),
                "Resource": safe_value(item.get("resource")),
                "Status": "FAILED",
                "Severity": safe_value(item.get("severity")) or "UNKNOWN",
                "File": safe_value(item.get("file_path")),
                "Line": safe_value(get_line_number(item)),
                "Guideline": safe_value(item.get("guideline")),
                "Code": safe_value(item.get("code_block"))
            }
        )

    for item in passed:
        results.append(
            {
                "Check ID": safe_value(item.get("check_id")),
                "Check": safe_value(item.get("check_name")),
                "Resource": safe_value(item.get("resource")),
                "Status": "PASSED",
                "Severity": safe_value(item.get("severity")) or "UNKNOWN",
                "File": safe_value(item.get("file_path")),
                "Line": safe_value(get_line_number(item)),
                "Guideline": safe_value(item.get("guideline")),
                "Code": safe_value(item.get("code_block"))
            }
        )

    for item in skipped:
        results.append(
            {
                "Check ID": safe_value(item.get("check_id")),
                "Check": safe_value(item.get("check_name")),
                "Resource": safe_value(item.get("resource")),
                "Status": "SKIPPED",
                "Severity": safe_value(item.get("severity")) or "UNKNOWN",
                "File": safe_value(item.get("file_path")),
                "Line": safe_value(get_line_number(item)),
                "Guideline": safe_value(item.get("guideline")),
                "Code": safe_value(item.get("code_block"))
            }
        )

    return results


def run_checkov(code, filename="main.tf"):
    suffix = ".tf"

    if filename.lower().endswith(".tf"):
        suffix = ".tf"

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8"
        ) as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name

        command = get_checkov_command(temp_path)

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        combined = process.stdout

        if process.stderr:
            combined += "\n" + process.stderr

        data = extract_json(process.stdout)

        if data is None:
            data = extract_json(combined)

        if data is None:
            return {
                "status": "ERROR",
                "findings": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "raw": combined,
                "error": "Checkov did not return readable JSON output."
            }

        findings = parse_checkov_results(data)

        failed_count = len(
            data.get("results", {}).get("failed_checks", [])
        )

        passed_count = len(
            data.get("results", {}).get("passed_checks", [])
        )

        skipped_count = len(
            data.get("results", {}).get("skipped_checks", [])
        )

        status = "FAILED" if failed_count > 0 else "PASSED"

        return {
            "status": status,
            "findings": findings,
            "passed": passed_count,
            "failed": failed_count,
            "skipped": skipped_count,
            "raw": data,
            "error": ""
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "ERROR",
            "findings": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "raw": "",
            "error": "Checkov validation timed out."
        }

    except Exception as exc:
        return {
            "status": "ERROR",
            "findings": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "raw": "",
            "error": str(exc)
        }

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def scan_current_configuration():
    result = run_checkov(
        st.session_state.code,
        st.session_state.filename
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scan_record = {
        "Time": now,
        "File": st.session_state.filename,
        "Status": result["status"],
        "Passed": result["passed"],
        "Failed": result["failed"],
        "Skipped": result["skipped"],
        "Issues": result["failed"]
    }

    st.session_state.last_scan = result
    st.session_state.findings = result["findings"]

    st.session_state.scan_history.insert(0, scan_record)

    add_audit(
        "Checkov validation",
        f'{result["status"]} | Failed: {result["failed"]} | Passed: {result["passed"]}'
    )

    return result


def fallback_ai_explanation(findings, code):
    failed = [
        item for item in findings
        if item.get("Status") == "FAILED"
    ]

    if not failed:
        return (
            "The latest Checkov validation did not report failed checks. "
            "The configuration passed the currently configured Checkov policies."
        )

    sections = []

    for item in failed[:10]:
        check_id = item.get("Check ID", "Unknown")
        check_name = item.get("Check", "Security policy violation")
        resource = item.get("Resource", "Unknown resource")
        guideline = item.get("Guideline", "")

        section = (
            f"Check ID: {check_id}\n"
            f"Problem: {check_name}\n"
            f"Resource: {resource}\n"
            f"Why it matters: This configuration does not satisfy the security policy represented by this Checkov check."
        )

        if guideline:
            section += f"\nReference: {guideline}"

        sections.append(section)

    return "\n\n".join(sections)


def redact_for_ai(text):
    replacements = [
        ("password", "[REDACTED_PASSWORD]"),
        ("secret", "[REDACTED_SECRET]"),
        ("api_key", "[REDACTED_API_KEY]"),
        ("access_key", "[REDACTED_ACCESS_KEY]"),
        ("private_key", "[REDACTED_PRIVATE_KEY]")
    ]

    output = text

    for key, replacement in replacements:
        lines = output.splitlines()

        for index, line in enumerate(lines):
            if key.lower() in line.lower() and "=" in line:
                left = line.split("=", 1)[0]
                lines[index] = left + '= "' + replacement + '"'

        output = "\n".join(lines)

    return output


def call_openai(explanation_context, code):
    api_key = st.secrets.get("OPENAI_API_KEY", "")

    if not api_key:
        return ""

    model = st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)

        prompt = f"""
You are an Infrastructure-as-Code security assistant.

Explain the Checkov findings below for a college project demonstration.

Give:
1. What went wrong
2. Why it is a security problem
3. Which Terraform resource is affected
4. A practical correction recommendation
5. A short before/after Terraform example when possible

Checkov findings:
{explanation_context}

Terraform:
{code}
"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2
        )

        return response.choices[0].message.content

    except Exception as exc:
        return f"AI provider error: {exc}"


def generate_ai_explanation():
    failed = [
        item for item in st.session_state.findings
        if item.get("Status") == "FAILED"
    ]

    if not failed:
        st.session_state.ai_explanation = fallback_ai_explanation(
            st.session_state.findings,
            st.session_state.code
        )
        return

    context = json.dumps(failed, indent=2)

    allow_ai = st.session_state.get("allow_ai_content", False)

    if allow_ai:
        ai_code = redact_for_ai(st.session_state.code)
        live_result = call_openai(context, ai_code)

        if live_result:
            st.session_state.ai_explanation = live_result
        else:
            st.session_state.ai_explanation = fallback_ai_explanation(
                st.session_state.findings,
                st.session_state.code
            )
    else:
        st.session_state.ai_explanation = fallback_ai_explanation(
            st.session_state.findings,
            st.session_state.code
        )

    add_audit("AI explanation generated")


def generate_suggestion():
    original = st.session_state.code

    corrected = original

    if "from_port   = 22" in corrected and "0.0.0.0/0" in corrected:
        corrected = corrected.replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/24"]',
            1
        )

    if corrected == original:
        failed = [
            item for item in st.session_state.findings
            if item.get("Status") == "FAILED"
        ]

        if failed:
            st.session_state.suggested_code = (
                "The application could not generate a deterministic "
                "automatic correction for the current findings. "
                "Review the Checkov guideline and modify the Terraform configuration."
            )
        else:
            st.session_state.suggested_code = original
    else:
        st.session_state.suggested_code = corrected

    add_audit("AI correction suggestion generated")


def apply_suggestion():
    if not st.session_state.suggested_code:
        return

    if st.session_state.suggested_code.startswith(
        "The application could not generate"
    ):
        return

    st.session_state.before_code = st.session_state.code
    st.session_state.code = st.session_state.suggested_code
    st.session_state.after_code = st.session_state.code

    add_audit("Suggested correction applied")


def create_diff(before, after):
    return "\n".join(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile="before.tf",
            tofile="after.tf",
            lineterm=""
        )
    )


def initialize_cvs():
    if shutil.which("cvs") is None:
        return None

    root = os.path.join(
        tempfile.gettempdir(),
        "ai_iac_cvs_" + uuid.uuid4().hex
    )

    repository = os.path.join(root, "repo")

    try:
        os.makedirs(root, exist_ok=True)

        process = subprocess.run(
            ["cvs", "-d", repository, "init"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if process.returncode != 0:
            return None

        return {
            "root": root,
            "repository": repository,
            "module": "iac"
        }

    except Exception:
        return None


if "cvs" not in st.session_state:
    st.session_state.cvs = initialize_cvs()


def cvs_import_initial():
    cvs = st.session_state.cvs

    if not cvs:
        return False

    if st.session_state.cvs_history:
        return True

    root = cvs["root"]
    repository = cvs["repository"]

    work_dir = os.path.join(root, "initial")
    os.makedirs(work_dir, exist_ok=True)

    with open(
        os.path.join(work_dir, st.session_state.filename),
        "w",
        encoding="utf-8"
    ) as file:
        file.write(st.session_state.code)

    process = subprocess.run(
        [
            "cvs",
            "-d",
            repository,
            "import",
            "-m",
            "Initial AI-IAC configuration",
            "iac",
            "AI-IAC",
            "START"
        ],
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=60
    )

    if process.returncode != 0:
        return False

    st.session_state.cvs_history.append(
        {
            "Revision": "1.1",
            "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Author": "student",
            "Description": "Initial configuration import",
            "Validation": "Not validated"
        }
    )

    return True


def cvs_commit(description, validation_status):
    cvs = st.session_state.cvs

    if not cvs:
        return False

    if not st.session_state.cvs_history:
        if not cvs_import_initial():
            return False

    root = cvs["root"]
    repository = cvs["repository"]
    checkout_dir = os.path.join(root, "checkout")

    if os.path.exists(checkout_dir):
        shutil.rmtree(checkout_dir)

    os.makedirs(checkout_dir, exist_ok=True)

    checkout = subprocess.run(
        [
            "cvs",
            "-d",
            repository,
            "checkout",
            "-d",
            "workspace",
            "iac"
        ],
        cwd=checkout_dir,
        capture_output=True,
        text=True,
        timeout=60
    )

    if checkout.returncode != 0:
        return False

    workspace = os.path.join(checkout_dir, "workspace")

    target = os.path.join(
        workspace,
        st.session_state.filename
    )

    with open(target, "w", encoding="utf-8") as file:
        file.write(st.session_state.code)

    subprocess.run(
        ["cvs", "add", st.session_state.filename],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=30
    )

    commit = subprocess.run(
        [
            "cvs",
            "commit",
            "-m",
            description
        ],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=60
    )

    if commit.returncode != 0:
        return False

    revision = "2.1"

    log_process = subprocess.run(
        [
            "cvs",
            "log",
            st.session_state.filename
        ],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=30
    )

    for line in log_process.stdout.splitlines():
        if line.startswith("revision "):
            revision = line.split("revision ", 1)[1].strip()
            break

    st.session_state.cvs_history.insert(
        0,
        {
            "Revision": revision,
            "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Author": "student",
            "Description": description,
            "Validation": validation_status
        }
    )

    add_audit(
        "CVS commit",
        f"{revision} | {validation_status}"
    )

    return True


def get_cvs_log():
    cvs = st.session_state.cvs

    if not cvs:
        return ""

    if not st.session_state.cvs_history:
        cvs_import_initial()

    root = cvs["root"]
    repository = cvs["repository"]
    checkout_dir = os.path.join(root, "log_workspace")

    if os.path.exists(checkout_dir):
        shutil.rmtree(checkout_dir)

    os.makedirs(checkout_dir, exist_ok=True)

    checkout = subprocess.run(
        [
            "cvs",
            "-d",
            repository,
            "checkout",
            "-d",
            "workspace",
            "iac"
        ],
        cwd=checkout_dir,
        capture_output=True,
        text=True,
        timeout=60
    )

    if checkout.returncode != 0:
        return ""

    workspace = os.path.join(checkout_dir, "workspace")

    process = subprocess.run(
        [
            "cvs",
            "log",
            st.session_state.filename
        ],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=30
    )

    return process.stdout


def create_json_report():
    report = {
        "project": "AI-IAC Configuration Validation",
        "generated_at": datetime.now().isoformat(),
        "filename": st.session_state.filename,
        "last_scan": st.session_state.last_scan,
        "findings": st.session_state.findings,
        "scan_history": st.session_state.scan_history,
        "audit_log": st.session_state.audit_log,
        "cvs_history": st.session_state.cvs_history
    }

    return json.dumps(
        report,
        indent=2,
        default=str
    )


def create_csv_report():
    output = io.StringIO()

    fields = [
        "Time",
        "File",
        "Status",
        "Passed",
        "Failed",
        "Skipped",
        "Issues"
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fields
    )

    writer.writeheader()

    for item in st.session_state.scan_history:
        writer.writerow(
            {
                field: item.get(field, "")
                for field in fields
            }
        )

    return output.getvalue()


def create_html_report():
    rows = ""

    for item in st.session_state.scan_history:
        rows += (
            "<tr>"
            f"<td>{html.escape(str(item.get('Time', '')))}</td>"
            f"<td>{html.escape(str(item.get('File', '')))}</td>"
            f"<td>{html.escape(str(item.get('Status', '')))}</td>"
            f"<td>{html.escape(str(item.get('Passed', '')))}</td>"
            f"<td>{html.escape(str(item.get('Failed', '')))}</td>"
            f"<td>{html.escape(str(item.get('Skipped', '')))}</td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>AI-IAC Validation Report</title>
<style>
body {{
font-family: Arial, sans-serif;
margin: 40px;
}}
table {{
border-collapse: collapse;
width: 100%;
}}
th, td {{
border: 1px solid #cccccc;
padding: 8px;
text-align: left;
}}
th {{
background: #eeeeee;
}}
</style>
</head>
<body>
<h1>AI-IAC Configuration Validation Report</h1>
<p>Generated: {html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
<p>Configuration: {html.escape(st.session_state.filename)}</p>
<table>
<thead>
<tr>
<th>Time</th>
<th>File</th>
<th>Status</th>
<th>Passed</th>
<th>Failed</th>
<th>Skipped</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def render_sidebar():
    st.sidebar.title("🛡️ AI-IAC Validator")

    pages = [
        "🏠 Dashboard",
        "📄 IaC Configuration",
        "🔍 Checkov Validation",
        "🚨 Security Findings",
        "🤖 AI Explanation",
        "✨ Suggested Correction",
        "🔄 Re-validation",
        "📊 Before / After",
        "📚 CVS History",
        "📝 Audit Log",
        "📈 Analytics",
        "📑 Reports",
        "⚙️ Settings",
        "🧪 Terraform Plan"
    ]

    selected = st.sidebar.radio(
        "Navigation",
        pages,
        index=pages.index(st.session_state.current_page)
    )

    st.session_state.current_page = selected

    st.sidebar.divider()

    st.sidebar.info(
        "Workflow: Terraform → CVS → Checkov → AI Explanation → "
        "Correction → Re-validation → CVS"
    )

    if st.session_state.last_scan:
        status = st.session_state.last_scan["status"]

        if status == "PASSED":
            st.sidebar.success("Latest Scan: PASSED")
        elif status == "FAILED":
            st.sidebar.error("Latest Scan: FAILED")
        else:
            st.sidebar.warning("Latest Scan: ERROR")


def page_dashboard():
    st.title("🏠 AI-IAC Configuration Validation")

    st.write(
        "AI-assisted Infrastructure-as-Code security validation using "
        "Terraform, Checkov, CVS and optional OpenAI integration."
    )

    total_scans = len(st.session_state.scan_history)
    passed_scans = sum(
        1 for item in st.session_state.scan_history
        if item["Status"] == "PASSED"
    )
    failed_scans = sum(
        1 for item in st.session_state.scan_history
        if item["Status"] == "FAILED"
    )
    total_issues = sum(
        item["Issues"]
        for item in st.session_state.scan_history
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Configurations Scanned", total_scans)
    col2.metric("Passed Scans", passed_scans)
    col3.metric("Failed Scans", failed_scans)
    col4.metric("Issues Found", total_issues)

    st.divider()

    st.subheader("Current Configuration")

    col1, col2 = st.columns(2)

    with col1:
        st.write("File")
        st.code(st.session_state.filename)

    with col2:
        st.write("Validation Status")

        if st.session_state.last_scan:
            status = st.session_state.last_scan["status"]

            if status == "PASSED":
                st.success("PASSED")
            elif status == "FAILED":
                st.error("FAILED")
            else:
                st.warning("ERROR")
        else:
            st.info("No scan performed yet.")

    st.divider()

    st.subheader("Validation Workflow")

    st.markdown(
        """
        **1. Create / Upload Terraform**
        
        ↓
        
        **2. CVS Version Tracking**
        
        ↓
        
        **3. Checkov Security Validation**
        
        ↓
        
        **4. Security Findings**
        
        ↓
        
        **5. AI Explanation**
        
        ↓
        
        **6. Suggested Correction**
        
        ↓
        
        **7. Re-validation**
        
        ↓
        
        **8. CVS Validated Revision**
        """
    )

    st.divider()

    st.subheader("Recent Validation History")

    if st.session_state.scan_history:
        if pd is not None:
            st.dataframe(
                pd.DataFrame(
                    st.session_state.scan_history
                ),
                use_container_width=True,
                hide_index=True
            )
    else:
        st.info("No validation history yet.")

    st.caption(
        "PASS means no failed Checkov checks were reported under the "
        "currently configured policies. It does not guarantee complete security."
    )


def page_iac():
    st.title("📄 IaC Configuration")

    st.write(
        "Upload, edit, or load a Terraform configuration."
    )

    uploaded = st.file_uploader(
        "Upload Terraform file",
        type=["tf"]
    )

    if uploaded is not None:
        content = uploaded.read().decode(
            "utf-8",
            errors="replace"
        )

        if st.button("Load Uploaded Configuration"):
            set_code(
                content,
                uploaded.name
            )
            st.rerun()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button(
            "🚨 Load Unsafe Demo",
            use_container_width=True
        ):
            set_code(
                UNSAFE_TERRAFORM,
                "unsafe_demo.tf"
            )
            st.rerun()

    with col2:
        if st.button(
            "✅ Load Safe Demo",
            use_container_width=True
        ):
            set_code(
                SAFE_TERRAFORM,
                "safe_demo.tf"
            )
            st.rerun()

    with col3:
        if st.button(
            "🧹 Clear",
            use_container_width=True
        ):
            set_code(
                "",
                "main.tf"
            )
            st.rerun()

    with col4:
        st.download_button(
            "📥 Download Terraform",
            data=st.session_state.code,
            file_name=st.session_state.filename,
            mime="text/plain",
            use_container_width=True
        )

    st.divider()

    st.session_state.code = st.text_area(
        "Terraform Configuration",
        value=st.session_state.code,
        height=500
    )

    st.session_state.filename = st.text_input(
        "Filename",
        value=st.session_state.filename
    )

    if st.button(
        "💾 Save Current Configuration",
        type="primary"
    ):
        add_audit(
            "Configuration edited",
            st.session_state.filename
        )
        st.success("Configuration saved in the current session.")


def page_checkov():
    st.title("🔍 Checkov Validation")

    st.write(
        "Run the actual Checkov scanner against the current Terraform configuration."
    )

    col1, col2 = st.columns([3, 1])

    with col1:
        st.code(st.session_state.filename)

    with col2:
        checkov_available = shutil.which("checkov")

        if checkov_available:
            st.success("Checkov detected")
        else:
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "checkov",
                        "--version"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    st.success("Checkov detected")
                else:
                    st.error("Checkov not detected")
            except Exception:
                st.error("Checkov not detected")

    if st.button(
        "🔍 Run Checkov Validation",
        type="primary",
        use_container_width=True
    ):
        with st.spinner("Running Checkov..."):
            result = scan_current_configuration()

        if result["status"] == "PASSED":
            st.success(
                f'PASS — {result["passed"]} passed, '
                f'{result["failed"]} failed, '
                f'{result["skipped"]} skipped'
            )

        elif result["status"] == "FAILED":
            st.error(
                f'FAIL — {result["failed"]} failed checks found'
            )

        else:
            st.error(result["error"])

    if st.session_state.last_scan:
        result = st.session_state.last_scan

        st.divider()

        c1, c2, c3 = st.columns(3)

        c1.metric("Passed", result["passed"])
        c2.metric("Failed", result["failed"])
        c3.metric("Skipped", result["skipped"])

        if result["status"] == "PASSED":
            st.success("Current Terraform configuration passed Checkov.")
        elif result["status"] == "FAILED":
            st.error("Current Terraform configuration failed Checkov.")
        else:
            st.warning("Checkov returned an error.")

        if result.get("error"):
            st.warning(result["error"])


def page_findings():
    st.title("🚨 Security Findings")

    if not st.session_state.findings:
        st.info(
            "Run Checkov validation first."
        )
        return

    failed = [
        item for item in st.session_state.findings
        if item["Status"] == "FAILED"
    ]

    passed = [
        item for item in st.session_state.findings
        if item["Status"] == "PASSED"
    ]

    skipped = [
        item for item in st.session_state.findings
        if item["Status"] == "SKIPPED"
    ]

    c1, c2, c3 = st.columns(3)

    c1.metric("Failed", len(failed))
    c2.metric("Passed", len(passed))
    c3.metric("Skipped", len(skipped))

    st.divider()

    search = st.text_input(
        "Search findings",
        placeholder="Check ID, resource, description..."
    )

    severity = st.selectbox(
        "Severity",
        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    )

    filtered = st.session_state.findings

    if search:
        term = search.lower()

        filtered = [
            item for item in filtered
            if term in json.dumps(
                item,
                ensure_ascii=False
            ).lower()
        ]

    if severity != "All":
        filtered = [
            item for item in filtered
            if item["Severity"].upper() == severity
        ]

    if pd is not None:
        display_columns = [
            "Check ID",
            "Check",
            "Resource",
            "Status",
            "Severity",
            "File",
            "Line",
            "Guideline"
        ]

        st.dataframe(
            pd.DataFrame(filtered)[display_columns],
            use_container_width=True,
            hide_index=True
        )

    st.divider()

    st.subheader("Finding Details")

    if filtered:
        options = [
            f'{item["Check ID"]} — {item["Resource"]}'
            for item in filtered
        ]

        selected = st.selectbox(
            "Select finding",
            options
        )

        index = options.index(selected)
        item = filtered[index]

        st.write("Check ID")
        st.code(item["Check ID"])

        st.write("Check")
        st.write(item["Check"])

        st.write("Resource")
        st.code(item["Resource"])

        st.write("Status")
        st.write(item["Status"])

        st.write("Severity")
        st.write(item["Severity"])

        st.write("File")
        st.code(item["File"])

        st.write("Line")
        st.write(item["Line"])

        st.write("Guideline")
        if item["Guideline"]:
            st.write(item["Guideline"])
        else:
            st.write("No guideline returned by Checkov.")

        st.write("Code involved")

        if item["Code"]:
            st.code(item["Code"], language="terraform")
        else:
            st.info("No code block returned by Checkov.")


def page_ai():
    st.title("🤖 AI Explanation")

    if not st.session_state.findings:
        st.info("Run Checkov first.")
        return

    failed = [
        item for item in st.session_state.findings
        if item["Status"] == "FAILED"
    ]

    if not failed:
        st.success(
            "No failed Checkov findings are currently available for explanation."
        )
        return

    st.checkbox(
        "Allow Terraform content to be sent to the configured AI provider",
        key="allow_ai_content"
    )

    if st.button(
        "🤖 Generate AI Explanation",
        type="primary"
    ):
        with st.spinner("Generating explanation..."):
            generate_ai_explanation()

    if st.session_state.ai_explanation:
        st.divider()

        st.markdown(
            st.session_state.ai_explanation
        )


def page_correction():
    st.title("✨ Suggested Correction")

    if not st.session_state.findings:
        st.info("Run Checkov first.")
        return

    if st.button(
        "✨ Generate Suggested Correction",
        type="primary"
    ):
        generate_suggestion()

    if st.session_state.suggested_code:
        st.divider()

        st.subheader("Suggested Configuration")

        if st.session_state.suggested_code.startswith(
            "The application could not generate"
        ):
            st.warning(
                st.session_state.suggested_code
            )
            return

        st.code(
            st.session_state.suggested_code,
            language="terraform"
        )

        if st.button(
            "✅ Apply Suggested Correction",
            use_container_width=True
        ):
            apply_suggestion()
            st.success(
                "Suggested correction applied. Run re-validation next."
            )
            st.rerun()


def page_revalidation():
    st.title("🔄 Re-validation")

    st.write(
        "Run Checkov again after applying a correction."
    )

    if st.button(
        "🔄 Re-validate Current Configuration",
        type="primary",
        use_container_width=True
    ):
        previous_findings = {
            item["Check ID"]
            for item in st.session_state.findings
            if item["Status"] == "FAILED"
        }

        result = scan_current_configuration()

        current_failed = {
            item["Check ID"]
            for item in result["findings"]
            if item["Status"] == "FAILED"
        }

        resolved = previous_findings - current_failed
        unresolved = previous_findings & current_failed

        if result["status"] == "PASSED":
            st.success(
                "Re-validation PASSED. The current configuration has no failed Checkov checks."
            )
            st.session_state.validation_gate = True

        elif result["status"] == "FAILED":
            st.error(
                f'Re-validation FAILED with {result["failed"]} failed checks.'
            )
            st.session_state.validation_gate = False

        else:
            st.warning(
                "Re-validation could not be completed."
            )

        st.divider()

        c1, c2 = st.columns(2)

        with c1:
            st.metric(
                "Resolved Previous Findings",
                len(resolved)
            )

        with c2:
            st.metric(
                "Unresolved Findings",
                len(unresolved)
            )

        if resolved:
            st.success(
                "Resolved: " + ", ".join(sorted(resolved))
            )

        if unresolved:
            st.warning(
                "Still present: " + ", ".join(sorted(unresolved))
            )


def page_before_after():
    st.title("📊 Before / After")

    before = st.session_state.before_code
    after = st.session_state.after_code

    if not before:
        st.info(
            "Apply a suggested correction to create a before/after comparison."
        )
        return

    if not after:
        after = st.session_state.code

    st.subheader("Configuration Comparison")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Before")
        st.code(
            before,
            language="terraform"
        )

    with col2:
        st.markdown("### After")
        st.code(
            after,
            language="terraform"
        )

    st.divider()

    st.subheader("Diff")

    diff = create_diff(
        before,
        after
    )

    if diff:
        st.code(diff)
    else:
        st.info("No changes detected.")

    st.divider()

    st.subheader("Validation Comparison")

    if st.session_state.scan_history:
        latest = st.session_state.scan_history[0]

        st.write(
            f'Latest validation status: **{latest["Status"]}**'
        )

        st.write(
            f'Current issue count: **{latest["Issues"]}**'
        )

    st.write(
        "For a full before/after validation comparison, run Checkov "
        "before changing the configuration and again after the correction."
    )


def page_cvs():
    st.title("📚 CVS History")

    if st.session_state.cvs:
        st.success(
            "CVS is available in this environment."
        )

        st.caption(
            "The CVS repository is session-local for this demonstration. "
            "It is not a permanent external CVS server."
        )

        if st.button(
            "📦 Initialize Initial CVS Revision",
            use_container_width=True
        ):
            if cvs_import_initial():
                st.success(
                    "Initial configuration imported into CVS."
                )
            else:
                st.error(
                    "Could not initialize the CVS revision."
                )

        st.divider()

        validation_status = "Not validated"

        if st.session_state.last_scan:
            validation_status = st.session_state.last_scan["status"]

        can_commit = (
            validation_status == "PASSED"
            and st.session_state.validation_gate
        )

        st.write(
            f"Current validation gate: **{validation_status}**"
        )

        description = st.text_input(
            "CVS commit description",
            value="Validated Terraform configuration"
        )

        if st.button(
            "💾 Commit Validated Revision",
            disabled=not can_commit,
            use_container_width=True
        ):
            if cvs_commit(
                description,
                validation_status
            ):
                st.success(
                    "Validated configuration committed to CVS."
                )
            else:
                st.error(
                    "CVS commit failed."
                )

        if not can_commit:
            st.info(
                "The validation gate requires a successful re-validation "
                "before a revision can be marked as validated."
            )

        st.divider()

        if st.session_state.cvs_history:
            if pd is not None:
                st.dataframe(
                    pd.DataFrame(
                        st.session_state.cvs_history
                    ),
                    use_container_width=True,
                    hide_index=True
                )

        if st.button(
            "📜 Show CVS Log"
        ):
            log = get_cvs_log()

            if log:
                st.code(log)
            else:
                st.info(
                    "No CVS log is currently available."
                )

    else:
        st.warning(
            "CVS is not available. The application can still demonstrate "
            "scan history, but this is not a real CVS repository."
        )

        if st.session_state.scan_history and pd is not None:
            st.dataframe(
                pd.DataFrame(
                    st.session_state.scan_history
                ),
                use_container_width=True,
                hide_index=True
            )


def page_audit():
    st.title("📝 Audit Log")

    if not st.session_state.audit_log:
        st.info("No audit events yet.")
        return

    if pd is not None:
        st.dataframe(
            pd.DataFrame(
                st.session_state.audit_log
            ),
            use_container_width=True,
            hide_index=True
        )

    st.download_button(
        "📥 Download Audit Log",
        data=json.dumps(
            st.session_state.audit_log,
            indent=2
        ),
        file_name="audit_log.json",
        mime="application/json"
    )


def page_analytics():
    st.title("📈 Validation Statistics")

    if not st.session_state.scan_history:
        st.info(
            "Run Checkov scans to generate statistics."
        )
        return

    if pd is None:
        st.warning(
            "Pandas is not available."
        )
        return

    dataframe = pd.DataFrame(
        st.session_state.scan_history
    )

    st.subheader("Passed vs Failed Scans")

    status_counts = dataframe["Status"].value_counts()

    st.bar_chart(
        status_counts
    )

    st.subheader("Issues Found Per Scan")

    issues = dataframe[
        ["Time", "Issues"]
    ].set_index("Time")

    st.line_chart(
        issues
    )

    st.subheader("Scan History")

    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True
    )


def page_reports():
    st.title("📑 Reports")

    st.write(
        "Generate reports from the current validation session."
    )

    json_report = create_json_report()
    csv_report = create_csv_report()
    html_report = create_html_report()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.download_button(
            "📥 JSON Report",
            data=json_report,
            file_name="ai_iac_validation_report.json",
            mime="application/json",
            use_container_width=True
        )

    with col2:
        st.download_button(
            "📥 CSV Report",
            data=csv_report,
            file_name="ai_iac_validation_report.csv",
            mime="text/csv",
            use_container_width=True
        )

    with col3:
        st.download_button(
            "📥 HTML Report",
            data=html_report,
            file_name="ai_iac_validation_report.html",
            mime="text/html",
            use_container_width=True
        )

    st.divider()

    st.subheader("JSON Preview")

    st.code(
        json_report,
        language="json"
    )


def page_settings():
    st.title("⚙️ Settings")

    st.subheader("Checkov Filters")

    st.session_state.settings_check = st.text_input(
        "Check IDs to include",
        value=st.session_state.settings_check,
        placeholder="CKV_AWS_24,CKV_AWS_23"
    )

    st.session_state.settings_skip = st.text_input(
        "Check IDs to skip",
        value=st.session_state.settings_skip,
        placeholder="CKV_AWS_999"
    )

    st.divider()

    st.subheader("AI Provider")

    api_key_present = bool(
        st.secrets.get(
            "OPENAI_API_KEY",
            ""
        )
    )

    if api_key_present:
        st.success(
            "OPENAI_API_KEY is configured."
        )
    else:
        st.info(
            "OPENAI_API_KEY is not configured. "
            "The application will use its built-in explanation logic."
        )

    model = st.secrets.get(
        "OPENAI_MODEL",
        "gpt-4o-mini"
    )

    st.write(
        f"Configured model: **{model}**"
    )

    st.divider()

    st.subheader("CVS")

    if st.session_state.cvs:
        st.success(
            "CVS repository initialized for this session."
        )
    else:
        st.warning(
            "CVS is not available."
        )

    st.divider()

    st.subheader("Session")

    if st.button(
        "🔄 Reset Session",
        use_container_width=True
    ):
        keys = list(st.session_state.keys())

        for key in keys:
            del st.session_state[key]

        st.rerun()


def page_plan():
    st.title("🧪 Terraform Plan Validation")

    st.write(
        "Optional advanced validation for a Terraform plan JSON file."
    )

    uploaded = st.file_uploader(
        "Upload Terraform plan JSON",
        type=["json"]
    )

    if uploaded is None:
        st.info(
            "Upload a Terraform plan JSON file to continue."
        )
        return

    try:
        plan = json.loads(
            uploaded.read().decode(
                "utf-8",
                errors="replace"
            )
        )
    except Exception as exc:
        st.error(
            f"Invalid JSON: {exc}"
        )
        return

    if st.button(
        "🧪 Validate Terraform Plan",
        type="primary"
    ):
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False,
                encoding="utf-8"
            ) as temp_file:
                json.dump(
                    plan,
                    temp_file
                )
                temp_path = temp_file.name

            command = [
                sys.executable,
                "-m",
                "checkov",
                "-f",
                temp_path,
                "--framework",
                "terraform_plan",
                "--output",
                "json"
            ]

            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180
            )

            data = extract_json(
                process.stdout
            )

            if data is None:
                st.error(
                    "Checkov did not return readable JSON."
                )

                if process.stderr:
                    st.code(process.stderr)

                return

            findings = parse_checkov_results(
                data
            )

            failed = [
                item for item in findings
                if item["Status"] == "FAILED"
            ]

            if failed:
                st.error(
                    f"Terraform plan validation failed with {len(failed)} finding(s)."
                )
            else:
                st.success(
                    "Terraform plan passed the returned Checkov checks."
                )

            if pd is not None and findings:
                st.dataframe(
                    pd.DataFrame(findings),
                    use_container_width=True,
                    hide_index=True
                )

            st.session_state.plan_result = {
                "findings": findings,
                "raw": data
            }

            add_audit(
                "Terraform plan validation",
                f"Findings: {len(failed)}"
            )

        except Exception as exc:
            st.error(
                f"Plan validation error: {exc}"
            )

        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass


render_sidebar()

page = st.session_state.current_page

if page == "🏠 Dashboard":
    page_dashboard()

elif page == "📄 IaC Configuration":
    page_iac()

elif page == "🔍 Checkov Validation":
    page_checkov()

elif page == "🚨 Security Findings":
    page_findings()

elif page == "🤖 AI Explanation":
    page_ai()

elif page == "✨ Suggested Correction":
    page_correction()

elif page == "🔄 Re-validation":
    page_revalidation()

elif page == "📊 Before / After":
    page_before_after()

elif page == "📚 CVS History":
    page_cvs()

elif page == "📝 Audit Log":
    page_audit()

elif page == "📈 Analytics":
    page_analytics()

elif page == "📑 Reports":
    page_reports()

elif page == "⚙️ Settings":
    page_settings()

elif page == "🧪 Terraform Plan":
    page_plan()
