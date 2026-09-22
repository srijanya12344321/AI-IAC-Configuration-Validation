import os
import sys
import json
import csv
import difflib
import shutil
import tempfile
import subprocess
from datetime import datetime

import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI-IAC Validator",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>
    .main-title {
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 18px;
        color: #555;
        margin-bottom: 25px;
    }

    .status-pass {
        background: #dff6e7;
        padding: 14px;
        border-radius: 10px;
        color: #126b36;
        font-weight: 600;
    }

    .status-fail {
        background: #ffe1e1;
        padding: 14px;
        border-radius: 10px;
        color: #a40000;
        font-weight: 600;
    }

    .status-info {
        background: #e7f0ff;
        padding: 14px;
        border-radius: 10px;
        color: #174a9c;
        font-weight: 600;
    }

    .metric-card {
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #ddd;
        background: #fafafa;
    }

    div[data-testid="stMetric"] {
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# DEMO TERRAFORM CONFIGURATIONS
# ============================================================

UNSAFE_DEMO = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "demo" {
  name = "unsafe-demo-security-group"

  ingress {
    description = "SSH open to the internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


SAFE_DEMO = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "demo" {
  name = "safe-demo-security-group"

  ingress {
    description = "SSH restricted to internal network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


# ============================================================
# SESSION STATE
# ============================================================

def initialize_state():
    defaults = {
        "terraform_code": SAFE_DEMO,
        "filename": "safe_demo.tf",
        "checkov_result": None,
        "previous_code": "",
        "history": [],
        "audit_log": [],
        "ai_explanation": "",
        "suggested_code": "",
        "validation_history": [],
        "settings_check": "",
        "settings_skip": "",
        "selected_finding": None,
        "plan_json": "",
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_state()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def add_audit(action, details=""):
    st.session_state.audit_log.append(
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "details": details,
        }
    )


def add_history(message):
    st.session_state.history.append(
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": message,
            "filename": st.session_state.filename,
        }
    )


def get_checkov_path():
    """
    Find the Checkov executable installed by pip/Streamlit.
    """
    checkov_path = shutil.which("checkov")

    if checkov_path:
        return checkov_path

    # Sometimes executables are installed beside the Python executable.
    python_dir = os.path.dirname(sys.executable)

    possible_paths = [
        os.path.join(python_dir, "checkov"),
        os.path.join(python_dir, "checkov.exe"),
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    return None


def extract_json(text):
    """
    Try to extract a JSON object from command output.
    """
    if not text:
        return None

    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and end > start:
        candidate = text[start:end + 1]

        try:
            return json.loads(candidate)
        except Exception:
            pass

    return None


def parse_checkov_results(data):
    """
    Convert Checkov's JSON result into a simpler structure for the UI.
    """

    findings = []

    results = data.get("results", {})

    failed_checks = results.get("failed_checks", [])
    passed_checks = results.get("passed_checks", [])
    skipped_checks = results.get("skipped_checks", [])

    for item in failed_checks:
        findings.append(
            {
                "status": "FAILED",
                "check_id": item.get("check_id", "Unknown"),
                "check_name": item.get(
                    "check_name",
                    item.get("check", "Unknown check")
                ),
                "severity": item.get("severity", "UNKNOWN"),
                "resource": item.get(
                    "resource",
                    item.get("resource_address", "Unknown")
                ),
                "file_path": item.get("file_path", ""),
                "file_line_range": item.get(
                    "file_line_range",
                    ""
                ),
                "guideline": item.get("guideline", ""),
                "code_block": item.get("code_block", []),
            }
        )

    for item in passed_checks:
        findings.append(
            {
                "status": "PASSED",
                "check_id": item.get("check_id", "Unknown"),
                "check_name": item.get(
                    "check_name",
                    item.get("check", "Unknown check")
                ),
                "severity": item.get("severity", "UNKNOWN"),
                "resource": item.get(
                    "resource",
                    item.get("resource_address", "Unknown")
                ),
                "file_path": item.get("file_path", ""),
                "file_line_range": item.get(
                    "file_line_range",
                    ""
                ),
                "guideline": item.get("guideline", ""),
                "code_block": item.get("code_block", []),
            }
        )

    for item in skipped_checks:
        findings.append(
            {
                "status": "SKIPPED",
                "check_id": item.get("check_id", "Unknown"),
                "check_name": item.get(
                    "check_name",
                    item.get("check", "Unknown check")
                ),
                "severity": item.get("severity", "UNKNOWN"),
                "resource": item.get(
                    "resource",
                    item.get("resource_address", "Unknown")
                ),
                "file_path": item.get("file_path", ""),
                "file_line_range": item.get(
                    "file_line_range",
                    ""
                ),
                "guideline": item.get("guideline", ""),
                "code_block": item.get("code_block", []),
            }
        )

    return findings


# ============================================================
# CORRECTED CHECKOV FUNCTION
# ============================================================

def run_checkov(code, filename="main.tf"):
    """
    Run the installed Checkov CLI against a temporary Terraform file.

    Important:
    We intentionally DO NOT use:

        python -m checkov

    because the deployed Checkov package may not expose checkov.main
    as a runnable Python module.

    Instead we execute the installed `checkov` command directly.
    """

    temp_path = None
    output_dir = None

    try:

        # --------------------------------------------------------
        # Check whether Checkov is installed
        # --------------------------------------------------------

        checkov_path = get_checkov_path()

        if not checkov_path:
            return {
                "status": "ERROR",
                "findings": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "raw": "",
                "error": (
                    "Checkov executable was not found. "
                    "Make sure 'checkov' is present in requirements.txt "
                    "and wait for Streamlit to finish reinstalling dependencies."
                ),
            }

        # --------------------------------------------------------
        # Create temporary Terraform file
        # --------------------------------------------------------

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".tf",
            delete=False,
            encoding="utf-8",
        ) as temp_file:

            temp_file.write(code)
            temp_path = temp_file.name

        # --------------------------------------------------------
        # Temporary directory for Checkov JSON output
        # --------------------------------------------------------

        output_dir = tempfile.mkdtemp(
            prefix="checkov_output_"
        )

        # --------------------------------------------------------
        # Build Checkov command
        # --------------------------------------------------------

        command = [
            checkov_path,
            "-f",
            temp_path,
            "--framework",
            "terraform",
            "--output",
            "json",
            "--output-file-path",
            output_dir,
        ]

        # Optional selected checks
        if st.session_state.settings_check.strip():
            command.extend(
                [
                    "--check",
                    st.session_state.settings_check.strip(),
                ]
            )

        # IMPORTANT:
        # Checkov uses --skip-check, NOT --skip
        if st.session_state.settings_skip.strip():
            command.extend(
                [
                    "--skip-check",
                    st.session_state.settings_skip.strip(),
                ]
            )

        # --------------------------------------------------------
        # Run Checkov
        # --------------------------------------------------------

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
        )

        stdout = process.stdout or ""
        stderr = process.stderr or ""

        # --------------------------------------------------------
        # Locate JSON output
        # --------------------------------------------------------

        data = None

        if os.path.exists(output_dir):

            json_files = []

            for root, dirs, files in os.walk(output_dir):
                for name in files:
                    if name.lower().endswith(".json"):
                        json_files.append(
                            os.path.join(root, name)
                        )

            # Try every JSON file until a valid Checkov result
            # is found.
            for json_path in json_files:

                try:
                    with open(
                        json_path,
                        "r",
                        encoding="utf-8",
                    ) as result_file:

                        candidate = json.load(result_file)

                    if isinstance(candidate, dict):

                        if "results" in candidate:
                            data = candidate
                            break

                        if data is None:
                            data = candidate

                except Exception:
                    continue

        # --------------------------------------------------------
        # Fallback: JSON printed directly to stdout
        # --------------------------------------------------------

        if data is None:
            data = extract_json(stdout)

        # --------------------------------------------------------
        # If JSON still cannot be found
        # --------------------------------------------------------

        if data is None:

            error_message = (
                "Checkov did not produce a readable JSON result."
            )

            if stderr.strip():
                error_message += (
                    "\n\nCheckov message:\n"
                    + stderr[-4000:]
                )

            if stdout.strip():
                error_message += (
                    "\n\nCheckov output:\n"
                    + stdout[-4000:]
                )

            return {
                "status": "ERROR",
                "findings": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "raw": stdout,
                "error": error_message,
            }

        # --------------------------------------------------------
        # Parse results
        # --------------------------------------------------------

        results = data.get("results", {})

        failed_checks = results.get(
            "failed_checks",
            []
        )

        passed_checks = results.get(
            "passed_checks",
            []
        )

        skipped_checks = results.get(
            "skipped_checks",
            []
        )

        findings = parse_checkov_results(data)

        failed_count = len(failed_checks)
        passed_count = len(passed_checks)
        skipped_count = len(skipped_checks)

        # IMPORTANT:
        # Checkov normally returns a non-zero exit code when
        # security checks fail.
        #
        # That is NOT an application error.
        #
        # If JSON was successfully parsed, we use the actual
        # findings to determine PASS/FAIL.

        status = (
            "FAILED"
            if failed_count > 0
            else "PASSED"
        )

        return {
            "status": status,
            "findings": findings,
            "passed": passed_count,
            "failed": failed_count,
            "skipped": skipped_count,
            "raw": data,
            "error": "",
        }

    except subprocess.TimeoutExpired:

        return {
            "status": "ERROR",
            "findings": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "raw": "",
            "error": "Checkov validation timed out after 180 seconds.",
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "findings": [],
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "raw": "",
            "error": str(exc),
        }

    finally:

        if temp_path and os.path.exists(temp_path):

            try:
                os.remove(temp_path)
            except Exception:
                pass

        if output_dir and os.path.exists(output_dir):

            try:
                shutil.rmtree(output_dir)
            except Exception:
                pass


# ============================================================
# AI EXPLANATION
# ============================================================

def get_ai_explanation(finding):
    """
    Optional OpenAI explanation.

    If no API key is configured, use the built-in explanation
    so the application still works.
    """

    check_id = finding.get("check_id", "Unknown")
    check_name = finding.get(
        "check_name",
        "Security configuration issue",
    )
    resource = finding.get(
        "resource",
        "Unknown resource",
    )
    guideline = finding.get(
        "guideline",
        "",
    )

    api_key = None

    try:
        api_key = st.secrets.get(
            "OPENAI_API_KEY",
            None,
        )
    except Exception:
        api_key = None

    # --------------------------------------------------------
    # Built-in explanation
    # --------------------------------------------------------

    fallback = f"""
### Security Finding

**Check ID:** `{check_id}`

**Issue:** {check_name}

**Resource:** `{resource}`

### Why this matters

This Checkov policy identified a configuration that may increase
the security exposure of the infrastructure.

The configuration should be reviewed and restricted according
to the application's actual networking and access requirements.

### Recommended approach

1. Identify the resource producing the finding.
2. Review the network or permission configuration.
3. Restrict access to only the required sources.
4. Run Checkov again after making the correction.

### Checkov guidance

{guideline if guideline else "Review the Checkov policy documentation for this check."}
"""

    if not api_key:
        return fallback

    # --------------------------------------------------------
    # Optional OpenAI integration
    # --------------------------------------------------------

    try:

        from openai import OpenAI

        client = OpenAI(
            api_key=api_key
        )

        model = os.getenv(
            "OPENAI_MODEL",
            "gpt-4o-mini",
        )

        prompt = f"""
You are assisting with Terraform infrastructure security.

Explain this Checkov finding to a college student.

Check ID:
{check_id}

Check name:
{check_name}

Resource:
{resource}

Guideline:
{guideline}

Give:
1. What the problem means
2. Why it matters
3. What should be changed
4. How to validate the correction

Do not invent information that is not present in the finding.
"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            temperature=0.2,
        )

        return response.choices[0].message.content

    except Exception:
        return fallback


# ============================================================
# SUGGESTED CORRECTION
# ============================================================

def generate_correction(code, findings):
    """
    Generate a deterministic demo correction.

    This specifically handles the common demo finding where
    SSH is exposed to the entire internet.
    """

    corrected = code

    changed = False

    # Common unsafe SSH rule
    if (
        'from_port   = 22' in corrected
        and 'cidr_blocks = ["0.0.0.0/0"]' in corrected
    ):

        corrected = corrected.replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/24"]',
            1,
        )

        changed = True

    # Alternative spacing
    if (
        'from_port = 22' in corrected
        and 'cidr_blocks = ["0.0.0.0/0"]' in corrected
    ):

        corrected = corrected.replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/24"]',
            1,
        )

        changed = True

    if changed:
        return corrected

    # If no automatic demo correction exists,
    # return the original code.
    return corrected


# ============================================================
# DIFF
# ============================================================

def create_diff(old_code, new_code):
    return "".join(
        difflib.unified_diff(
            old_code.splitlines(True),
            new_code.splitlines(True),
            fromfile="Before",
            tofile="After",
        )
    )


# ============================================================
# REPORT GENERATION
# ============================================================

def create_report_data():
    result = st.session_state.checkov_result

    if not result:
        return {
            "generated_at": datetime.now().isoformat(),
            "filename": st.session_state.filename,
            "status": "NOT_RUN",
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "findings": [],
        }

    return {
        "generated_at": datetime.now().isoformat(),
        "filename": st.session_state.filename,
        "status": result.get("status"),
        "passed": result.get("passed", 0),
        "failed": result.get("failed", 0),
        "skipped": result.get("skipped", 0),
        "findings": result.get("findings", []),
    }


def report_json():
    return json.dumps(
        create_report_data(),
        indent=2,
        default=str,
    )


def report_csv():
    result = st.session_state.checkov_result

    rows = []

    if result:

        for finding in result.get(
            "findings",
            [],
        ):

            rows.append(
                {
                    "status": finding.get(
                        "status",
                        "",
                    ),
                    "check_id": finding.get(
                        "check_id",
                        "",
                    ),
                    "check_name": finding.get(
                        "check_name",
                        "",
                    ),
                    "severity": finding.get(
                        "severity",
                        "",
                    ),
                    "resource": finding.get(
                        "resource",
                        "",
                    ),
                    "file_path": finding.get(
                        "file_path",
                        "",
                    ),
                }
            )

    if not rows:

        rows.append(
            {
                "status": "",
                "check_id": "",
                "check_name": "",
                "severity": "",
                "resource": "",
                "file_path": "",
            }
        )

    output = []

    fieldnames = list(
        rows[0].keys()
    )

    output.append(
        ",".join(fieldnames)
    )

    for row in rows:

        output.append(
            ",".join(
                '"' + str(row[field]).replace('"', '""') + '"'
                for field in fieldnames
            )
        )

    return "\n".join(output)


def report_html():
    result = st.session_state.checkov_result

    status = (
        result.get("status")
        if result
        else "NOT RUN"
    )

    passed = (
        result.get("passed", 0)
        if result
        else 0
    )

    failed = (
        result.get("failed", 0)
        if result
        else 0
    )

    skipped = (
        result.get("skipped", 0)
        if result
        else 0
    )

    rows = ""

    if result:

        for finding in result.get(
            "findings",
            [],
        ):

            rows += f"""
            <tr>
                <td>{finding.get("status", "")}</td>
                <td>{finding.get("check_id", "")}</td>
                <td>{finding.get("check_name", "")}</td>
                <td>{finding.get("severity", "")}</td>
                <td>{finding.get("resource", "")}</td>
            </tr>
            """

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>AI-IAC Validator Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
}}

th {{
    background: #f2f2f2;
}}
</style>
</head>

<body>

<h1>AI-IAC Validator Report</h1>

<p>
<b>Generated:</b>
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</p>

<p>
<b>Terraform file:</b>
{st.session_state.filename}
</p>

<h2>Validation Summary</h2>

<p>
Status: <b>{status}</b>
</p>

<ul>
<li>Passed: {passed}</li>
<li>Failed: {failed}</li>
<li>Skipped: {skipped}</li>
</ul>

<h2>Findings</h2>

<table>

<tr>
<th>Status</th>
<th>Check ID</th>
<th>Check Name</th>
<th>Severity</th>
<th>Resource</th>
</tr>

{rows}

</table>

</body>
</html>
"""


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🔎 AI-IAC Validator")

pages = [
    "Dashboard",
    "IaC Configuration",
    "Checkov Validation",
    "Security Findings",
    "AI Explanation",
    "Suggested Correction",
    "Re-validation",
    "Before/After",
    "CVS History",
    "Audit Log",
    "Analytics",
    "Reports",
    "Settings",
    "Terraform Plan",
]

page = st.sidebar.radio(
    "Navigation",
    pages,
)

st.sidebar.divider()

st.sidebar.write(
    f"**File:** {st.session_state.filename}"
)

result = st.session_state.checkov_result

if result:

    if result["status"] == "PASSED":
        st.sidebar.success("Validation Passed")

    elif result["status"] == "FAILED":
        st.sidebar.error("Security Findings Found")

    else:
        st.sidebar.warning("Validation Error")

else:
    st.sidebar.info("Validation not run")


# ============================================================
# DASHBOARD
# ============================================================

if page == "Dashboard":

    st.markdown(
        '<div class="main-title">🔎 AI-IAC Validator</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="subtitle">
        AI-assisted Infrastructure-as-Code configuration
        validation using Terraform and Checkov.
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)

    result = st.session_state.checkov_result

    passed = result["passed"] if result else 0
    failed = result["failed"] if result else 0
    skipped = result["skipped"] if result else 0

    col1.metric(
        "Passed",
        passed,
    )

    col2.metric(
        "Failed",
        failed,
    )

    col3.metric(
        "Skipped",
        skipped,
    )

    col4.metric(
        "Validations",
        len(
            st.session_state.validation_history
        ),
    )

    st.divider()

    st.subheader("Project Workflow")

    workflow = [
        "1. Upload or edit Terraform",
        "2. Run Checkov validation",
        "3. Review security findings",
        "4. Generate AI explanation",
        "5. Generate suggested correction",
        "6. Re-validate corrected configuration",
        "7. Compare Before/After",
        "8. Generate report",
    ]

    for item in workflow:
        st.write("✅ " + item)

    st.divider()

    st.subheader("Current Configuration")

    st.code(
        st.session_state.terraform_code,
        language="hcl",
    )


# ============================================================
# IAC CONFIGURATION
# ============================================================

elif page == "IaC Configuration":

    st.title("🧩 IaC Configuration")

    st.write(
        "Upload, edit, validate, and download Terraform configuration."
    )

    uploaded_file = st.file_uploader(
        "Upload Terraform file",
        type=["tf"],
    )

    if uploaded_file:

        uploaded_code = uploaded_file.read().decode(
            "utf-8",
            errors="replace",
        )

        st.session_state.terraform_code = uploaded_code
        st.session_state.filename = uploaded_file.name

        add_audit(
            "Terraform uploaded",
            uploaded_file.name,
        )

        st.success(
            f"Loaded {uploaded_file.name}"
        )

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "Load Unsafe Demo",
            use_container_width=True,
        ):

            st.session_state.terraform_code = UNSAFE_DEMO
            st.session_state.filename = "unsafe_demo.tf"
            st.session_state.checkov_result = None

            add_history(
                "Loaded unsafe Terraform demo"
            )

            add_audit(
                "Demo loaded",
                "unsafe_demo.tf",
            )

            st.rerun()

    with col2:

        if st.button(
            "Load Safe Demo",
            use_container_width=True,
        ):

            st.session_state.terraform_code = SAFE_DEMO
            st.session_state.filename = "safe_demo.tf"
            st.session_state.checkov_result = None

            add_history(
                "Loaded safe Terraform demo"
            )

            add_audit(
                "Demo loaded",
                "safe_demo.tf",
            )

            st.rerun()

    st.divider()

    filename = st.text_input(
        "Terraform filename",
        value=st.session_state.filename,
    )

    st.session_state.filename = filename

    code = st.text_area(
        "Terraform configuration",
        value=st.session_state.terraform_code,
        height=500,
    )

    if code != st.session_state.terraform_code:

        st.session_state.previous_code = (
            st.session_state.terraform_code
        )

        st.session_state.terraform_code = code

    st.download_button(
        "⬇️ Download Terraform",
        data=st.session_state.terraform_code,
        file_name=st.session_state.filename,
        mime="text/plain",
        use_container_width=True,
    )


# ============================================================
# CHECKOV VALIDATION
# ============================================================

elif page == "Checkov Validation":

    st.title("🔍 Checkov Validation")

    st.write(
        "Run the actual Checkov scanner against the current Terraform configuration."
    )

    col1, col2 = st.columns([3, 1])

    with col1:
        st.info(
            st.session_state.filename
        )

    with col2:

        checkov_path = get_checkov_path()

        if checkov_path:
            st.success("Checkov detected")
        else:
            st.error("Checkov not detected")

    if st.button(
        "🔎 Run Checkov Validation",
        use_container_width=True,
        type="primary",
    ):

        with st.spinner(
            "Running Checkov..."
        ):

            result = run_checkov(
                st.session_state.terraform_code,
                st.session_state.filename,
            )

        st.session_state.checkov_result = result

        st.session_state.validation_history.append(
            {
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "filename": st.session_state.filename,
                "status": result["status"],
                "passed": result["passed"],
                "failed": result["failed"],
                "skipped": result["skipped"],
            }
        )

        add_history(
            f"Checkov validation: {result['status']}"
        )

        add_audit(
            "Checkov validation",
            result["status"],
        )

        st.rerun()

    result = st.session_state.checkov_result

    if result:

        if result["status"] == "PASSED":

            st.success(
                "Checkov validation passed."
            )

        elif result["status"] == "FAILED":

            st.error(
                "Checkov found security issues."
            )

        else:

            st.error(
                result.get(
                    "error",
                    "Checkov returned an error.",
                )
            )

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Passed",
            result["passed"],
        )

        col2.metric(
            "Failed",
            result["failed"],
        )

        col3.metric(
            "Skipped",
            result["skipped"],
        )

        if result.get("error"):

            st.warning(
                result["error"]
            )


# ============================================================
# SECURITY FINDINGS
# ============================================================

elif page == "Security Findings":

    st.title("🚨 Security Findings")

    result = st.session_state.checkov_result

    if not result:

        st.info(
            "Run Checkov validation first."
        )

    else:

        findings = result.get(
            "findings",
            [],
        )

        failed_findings = [
            item
            for item in findings
            if item["status"] == "FAILED"
        ]

        st.metric(
            "Security findings",
            len(failed_findings),
        )

        search = st.text_input(
            "Search findings"
        )

        severity = st.selectbox(
            "Severity",
            [
                "All",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN",
            ],
        )

        filtered = failed_findings

        if search:

            search_lower = search.lower()

            filtered = [
                item
                for item in filtered
                if search_lower in (
                    str(item).lower()
                )
            ]

        if severity != "All":

            filtered = [
                item
                for item in filtered
                if item.get(
                    "severity",
                    "UNKNOWN",
                ) == severity
            ]

        if not filtered:

            st.success(
                "No matching failed checks."
            )

        for index, finding in enumerate(
            filtered
        ):

            with st.expander(
                f"{finding['check_id']} — "
                f"{finding['check_name']}"
            ):

                st.write(
                    "**Severity:**",
                    finding.get(
                        "severity",
                        "UNKNOWN",
                    ),
                )

                st.write(
                    "**Resource:**",
                    finding.get(
                        "resource",
                        "",
                    ),
                )

                st.write(
                    "**File:**",
                    finding.get(
                        "file_path",
                        "",
                    ),
                )

                st.write(
                    "**Line:**",
                    finding.get(
                        "file_line_range",
                        "",
                    ),
                )

                if finding.get(
                    "guideline"
                ):

                    st.write(
                        "**Guideline:**"
                    )

                    st.write(
                        finding["guideline"]
                    )

                if st.button(
                    "Explain this finding",
                    key=f"explain_{index}",
                ):

                    st.session_state.selected_finding = finding
                    st.session_state.ai_explanation = (
                        get_ai_explanation(
                            finding
                        )
                    )

                    add_audit(
                        "AI explanation generated",
                        finding["check_id"],
                    )

                    st.rerun()


# ============================================================
# AI EXPLANATION
# ============================================================

elif page == "AI Explanation":

    st.title("🤖 AI Explanation")

    finding = st.session_state.selected_finding

    if not finding:

        result = st.session_state.checkov_result

        if result:

            failed = [
                item
                for item in result.get(
                    "findings",
                    [],
                )
                if item["status"] == "FAILED"
            ]

            if failed:

                finding = failed[0]

                st.session_state.selected_finding = finding

    if not finding:

        st.info(
            "Select a security finding from the Security Findings page."
        )

    else:

        st.write(
            f"**{finding['check_id']} — "
            f"{finding['check_name']}**"
        )

        if st.button(
            "🤖 Generate AI Explanation",
            type="primary",
        ):

            with st.spinner(
                "Generating explanation..."
            ):

                explanation = get_ai_explanation(
                    finding
                )

            st.session_state.ai_explanation = explanation

            add_audit(
                "AI explanation generated",
                finding["check_id"],
            )

        if st.session_state.ai_explanation:

            st.markdown(
                st.session_state.ai_explanation
            )


# ============================================================
# SUGGESTED CORRECTION
# ============================================================

elif page == "Suggested Correction":

    st.title("🛠️ Suggested Correction")

    result = st.session_state.checkov_result

    if not result:

        st.info(
            "Run Checkov first."
        )

    elif result["failed"] == 0:

        st.success(
            "No failed checks require correction."
        )

    else:

        if st.button(
            "Generate Suggested Correction",
            type="primary",
        ):

            corrected = generate_correction(
                st.session_state.terraform_code,
                result.get(
                    "findings",
                    [],
                ),
            )

            st.session_state.suggested_code = corrected

            add_audit(
                "Suggested correction generated"
            )

            st.rerun()

        if st.session_state.suggested_code:

            st.subheader(
                "Corrected Terraform"
            )

            st.code(
                st.session_state.suggested_code,
                language="hcl",
            )

            col1, col2 = st.columns(2)

            with col1:

                if st.button(
                    "Apply Suggested Correction",
                    use_container_width=True,
                ):

                    st.session_state.previous_code = (
                        st.session_state.terraform_code
                    )

                    st.session_state.terraform_code = (
                        st.session_state.suggested_code
                    )

                    st.session_state.filename = (
                        "corrected_" +
                        st.session_state.filename
                    )

                    add_history(
                        "Applied suggested correction"
                    )

                    add_audit(
                        "Correction applied"
                    )

                    st.success(
                        "Correction applied."
                    )

            with col2:

                st.download_button(
                    "Download Corrected Terraform",
                    data=st.session_state.suggested_code,
                    file_name="corrected_"
                    + st.session_state.filename,
                    mime="text/plain",
                    use_container_width=True,
                )


# ============================================================
# RE-VALIDATION
# ============================================================

elif page == "Re-validation":

    st.title("🔄 Re-validation")

    st.write(
        "Run Checkov again after applying a correction."
    )

    if st.button(
        "🔄 Re-run Checkov",
        type="primary",
        use_container_width=True,
    ):

        with st.spinner(
            "Re-validating..."
        ):

            result = run_checkov(
                st.session_state.terraform_code,
                st.session_state.filename,
            )

        st.session_state.checkov_result = result

        st.session_state.validation_history.append(
            {
                "timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "filename": st.session_state.filename,
                "status": result["status"],
                "passed": result["passed"],
                "failed": result["failed"],
                "skipped": result["skipped"],
            }
        )

        add_history(
            "Re-validation completed"
        )

        add_audit(
            "Re-validation",
            result["status"],
        )

        st.rerun()

    result = st.session_state.checkov_result

    if result:

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Passed",
            result["passed"],
        )

        col2.metric(
            "Failed",
            result["failed"],
        )

        col3.metric(
            "Skipped",
            result["skipped"],
        )

        if result["status"] == "PASSED":

            st.success(
                "✅ Validation Gate: PASSED"
            )

        elif result["status"] == "FAILED":

            st.error(
                "❌ Validation Gate: FAILED"
            )

        else:

            st.warning(
                "⚠️ Validation Gate: ERROR"
            )


# ============================================================
# BEFORE / AFTER
# ============================================================

elif page == "Before/After":

    st.title("↔️ Before / After")

    old_code = st.session_state.previous_code
    new_code = st.session_state.terraform_code

    if not old_code:

        st.info(
            "No previous configuration is available yet."
        )

    else:

        col1, col2 = st.columns(2)

        with col1:

            st.subheader("Before")

            st.code(
                old_code,
                language="hcl",
            )

        with col2:

            st.subheader("After")

            st.code(
                new_code,
                language="hcl",
            )

        st.subheader(
            "Configuration Diff"
        )

        diff = create_diff(
            old_code,
            new_code,
        )

        if diff:

            st.code(
                diff,
                language="diff",
            )

        else:

            st.info(
                "No differences detected."
            )


# ============================================================
# CVS HISTORY
# ============================================================

elif page == "CVS History":

    st.title("🗂️ CVS History")

    st.write(
        "Local session history of configuration and validation events."
    )

    if not st.session_state.history:

        st.info(
            "No history available."
        )

    else:

        history_df = pd.DataFrame(
            st.session_state.history
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

    st.divider()

    if st.button(
        "Create Version Snapshot"
    ):

        snapshot = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "filename": st.session_state.filename,
            "code": st.session_state.terraform_code,
        }

        st.session_state.history.append(
            {
                "timestamp": snapshot["timestamp"],
                "message": "Version snapshot created",
                "filename": snapshot["filename"],
            }
        )

        add_audit(
            "Version snapshot created"
        )

        st.success(
            "Version snapshot created."
        )


# ============================================================
# AUDIT LOG
# ============================================================

elif page == "Audit Log":

    st.title("📋 Audit Log")

    if not st.session_state.audit_log:

        st.info(
            "No audit events yet."
        )

    else:

        audit_df = pd.DataFrame(
            st.session_state.audit_log
        )

        st.dataframe(
            audit_df,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# ANALYTICS
# ============================================================

elif page == "Analytics":

    st.title("📊 Analytics")

    history = st.session_state.validation_history

    if not history:

        st.info(
            "Run Checkov validations to generate analytics."
        )

    else:

        df = pd.DataFrame(
            history
        )

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Validations",
            len(df),
        )

        col2.metric(
            "Total Passed Checks",
            int(
                df["passed"].sum()
            ),
        )

        col3.metric(
            "Total Failed Checks",
            int(
                df["failed"].sum()
            ),
        )

        st.subheader(
            "Validation History"
        )

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

        chart_df = df[
            [
                "passed",
                "failed",
                "skipped",
            ]
        ]

        st.line_chart(
            chart_df
        )


# ============================================================
# REPORTS
# ============================================================

elif page == "Reports":

    st.title("📄 Reports")

    result = st.session_state.checkov_result

    if not result:

        st.info(
            "Run Checkov before generating a report."
        )

    else:

        st.subheader(
            "Validation Summary"
        )

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Status",
            result["status"],
        )

        col2.metric(
            "Passed",
            result["passed"],
        )

        col3.metric(
            "Failed",
            result["failed"],
        )

        col4.metric(
            "Skipped",
            result["skipped"],
        )

        st.divider()

        st.download_button(
            "⬇️ Download JSON Report",
            data=report_json(),
            file_name="iac_validation_report.json",
            mime="application/json",
            use_container_width=True,
        )

        st.download_button(
            "⬇️ Download CSV Report",
            data=report_csv(),
            file_name="iac_validation_report.csv",
            mime="text/csv",
            use_container_width=True,
        )

        st.download_button(
            "⬇️ Download HTML Report",
            data=report_html(),
            file_name="iac_validation_report.html",
            mime="text/html",
            use_container_width=True,
        )


# ============================================================
# SETTINGS
# ============================================================

elif page == "Settings":

    st.title("⚙️ Settings")

    st.subheader(
        "Checkov Policy Settings"
    )

    st.session_state.settings_check = st.text_input(
        "Run only these checks",
        value=st.session_state.settings_check,
        placeholder="Example: CKV_AWS_24,CKV_AWS_25",
    )

    st.session_state.settings_skip = st.text_input(
        "Skip these checks",
        value=st.session_state.settings_skip,
        placeholder="Example: CKV_AWS_18",
    )

    st.caption(
        "Use Checkov check IDs separated by commas."
    )

    st.divider()

    st.subheader(
        "Application"
    )

    if st.button(
        "Reset Session",
        type="secondary",
    ):

        for key in list(
            st.session_state.keys()
        ):
            del st.session_state[key]

        st.rerun()


# ============================================================
# TERRAFORM PLAN
# ============================================================

elif page == "Terraform Plan":

    st.title("📦 Terraform Plan")

    st.write(
        "Paste Terraform plan JSON for basic structural validation."
    )

    plan_text = st.text_area(
        "Terraform Plan JSON",
        value=st.session_state.plan_json,
        height=400,
        placeholder='{"format_version":"1.0","terraform_version":"1.5.0"}',
    )

    st.session_state.plan_json = plan_text

    if st.button(
        "Validate Plan JSON",
        type="primary",
    ):

        try:

            data = json.loads(
                plan_text
            )

            st.success(
                "Valid JSON Terraform plan structure detected."
            )

            st.json(data)

            add_audit(
                "Terraform plan JSON validated"
            )

        except Exception as exc:

            st.error(
                f"Invalid JSON: {exc}"
            )


# ============================================================
# FOOTER
# ============================================================

st.sidebar.divider()

st.sidebar.caption(
    "AI-IAC Validator • Terraform + Checkov"
)
