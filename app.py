import os
import sys
import json
import csv
import shutil
import tempfile
import subprocess
from datetime import datetime

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="AI-IAC Validator",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)


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
    </style>
    """,
    unsafe_allow_html=True,
)


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
        "cvs_output": "",
        "cvs_repository": "",
        "cvs_module": "",
        "cvs_username": "",
        "cvs_password": "",
        "cvs_root": "",
        "cvs_workspace": "",
        "cvs_ready": False,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_state()


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


def get_executable(name):
    path = shutil.which(name)

    if path:
        return path

    python_dir = os.path.dirname(sys.executable)

    possible = [
        os.path.join(python_dir, name),
        os.path.join(python_dir, name + ".exe"),
    ]

    for item in possible:
        if os.path.exists(item):
            return item

    return None


def get_checkov_path():
    return get_executable("checkov")


def get_cvs_path():
    return get_executable("cvs")


def run_command(command, cwd=None, timeout=120, env=None):
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        return {
            "returncode": process.returncode,
            "stdout": process.stdout or "",
            "stderr": process.stderr or "",
            "error": "",
        }

    except FileNotFoundError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "error": f"Command not found: {command[0]}",
        }

    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "error": "Command timed out.",
        }

    except Exception as exc:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }


def extract_json(text):
    if not text:
        return None

    try:
        return json.loads(text.strip())
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            pass

    return None


def parse_checkov_results(data):
    findings = []

    results = data.get("results", {})

    failed_checks = results.get("failed_checks", [])
    passed_checks = results.get("passed_checks", [])
    skipped_checks = results.get("skipped_checks", [])

    for status, items in [
        ("FAILED", failed_checks),
        ("PASSED", passed_checks),
        ("SKIPPED", skipped_checks),
    ]:
        for item in items:
            findings.append(
                {
                    "status": status,
                    "check_id": item.get("check_id", "Unknown"),
                    "check_name": item.get(
                        "check_name",
                        item.get("check", "Unknown check"),
                    ),
                    "severity": item.get("severity", "UNKNOWN"),
                    "resource": item.get(
                        "resource",
                        item.get("resource_address", "Unknown"),
                    ),
                    "file_path": item.get("file_path", ""),
                    "file_line_range": item.get(
                        "file_line_range",
                        "",
                    ),
                    "guideline": item.get("guideline", ""),
                    "code_block": item.get("code_block", []),
                }
            )

    return findings


def run_checkov(code, filename="main.tf"):
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
                "Checkov was not found. Install it with "
                "'pip install checkov'."
            ),
        }

    temp_dir = tempfile.mkdtemp(prefix="iac_check_")
    temp_path = os.path.join(temp_dir, filename)

    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            file.write(code)

        output_dir = os.path.join(temp_dir, "checkov_output")
        os.makedirs(output_dir, exist_ok=True)

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

        if st.session_state.settings_check.strip():
            command.extend(
                [
                    "--check",
                    st.session_state.settings_check.strip(),
                ]
            )

        if st.session_state.settings_skip.strip():
            command.extend(
                [
                    "--skip-check",
                    st.session_state.settings_skip.strip(),
                ]
            )

        result = run_command(
            command,
            timeout=180,
        )

        data = None

        for root, _, files in os.walk(output_dir):
            for name in files:
                if name.lower().endswith(".json"):
                    path = os.path.join(root, name)

                    try:
                        with open(
                            path,
                            "r",
                            encoding="utf-8",
                        ) as file:
                            candidate = json.load(file)

                        if isinstance(candidate, dict):
                            data = candidate
                            break

                    except Exception:
                        continue

            if data:
                break

        if data is None:
            data = extract_json(result["stdout"])

        if data is None:
            return {
                "status": "ERROR",
                "findings": [],
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "raw": result["stdout"],
                "error": (
                    "Checkov did not produce readable JSON.\n\n"
                    + result["stderr"]
                ),
            }

        results = data.get("results", {})

        failed = results.get("failed_checks", [])
        passed = results.get("passed_checks", [])
        skipped = results.get("skipped_checks", [])

        return {
            "status": "FAILED" if failed else "PASSED",
            "findings": parse_checkov_results(data),
            "passed": len(passed),
            "failed": len(failed),
            "skipped": len(skipped),
            "raw": data,
            "error": "",
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
        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )


def get_ai_explanation(finding):
    check_id = finding.get(
        "check_id",
        "Unknown",
    )

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

    fallback = f"""
### Security Finding

**Check ID:** `{check_id}`

**Issue:** {check_name}

**Resource:** `{resource}`

### Why this matters

The Checkov policy identified a configuration
that may violate a security requirement.

### Recommended approach

Review the affected Terraform resource,
restrict unnecessary access, and run the
validation again.

### Checkov guidance

{guideline if guideline else "Review the applicable Checkov policy guidance."}
"""

    api_key = None

    try:
        api_key = st.secrets.get(
            "OPENAI_API_KEY",
            None,
        )
    except Exception:
        pass

    if not api_key:
        return fallback

    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key,
        )

        response = client.chat.completions.create(
            model=os.getenv(
                "OPENAI_MODEL",
                "gpt-4o-mini",
            ),
            messages=[
                {
                    "role": "user",
                    "content": f"""
Explain this Checkov Terraform security finding
to a college student.

Check ID: {check_id}
Check name: {check_name}
Resource: {resource}
Guideline: {guideline}

Explain:
1. What the problem means.
2. Why it matters.
3. What should be changed.
4. How to revalidate it.

Do not invent facts.
""",
                }
            ],
            temperature=0.2,
        )

        return response.choices[0].message.content

    except Exception:
        return fallback


def generate_correction(code):
    corrected = code

    changed = False

    if 'cidr_blocks = ["0.0.0.0/0"]' in corrected:
        corrected = corrected.replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/24"]',
            1,
        )

        changed = True

    if changed:
        return corrected

    return ""


# ============================================================
# CVS FUNCTIONS
# ============================================================

def cvs_environment():
    env = os.environ.copy()

    if st.session_state.cvs_root.strip():
        env["CVSROOT"] = st.session_state.cvs_root.strip()

    return env


def cvs_is_available():
    return get_cvs_path() is not None


def cvs_status():
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    result = run_command(
        [cvs_path, "--version"],
        timeout=30,
        env=cvs_environment(),
    )

    if result["returncode"] != 0:
        return {
            "ok": False,
            "message": result["stderr"] or result["error"],
        }

    return {
        "ok": True,
        "message": result["stdout"],
    }


def cvs_checkout(module, workspace):
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    os.makedirs(workspace, exist_ok=True)

    command = [
        cvs_path,
        "-d",
        st.session_state.cvs_root.strip(),
        "checkout",
        module,
    ]

    result = run_command(
        command,
        cwd=workspace,
        timeout=120,
        env=cvs_environment(),
    )

    ok = result["returncode"] == 0

    return {
        "ok": ok,
        "message": (
            result["stdout"]
            if ok
            else result["stderr"] or result["error"]
        ),
    }


def cvs_update(workspace):
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    result = run_command(
        [cvs_path, "update"],
        cwd=workspace,
        timeout=120,
        env=cvs_environment(),
    )

    return {
        "ok": result["returncode"] == 0,
        "message": (
            result["stdout"]
            if result["returncode"] == 0
            else result["stderr"] or result["error"]
        ),
    }


def cvs_add(workspace, filename):
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    result = run_command(
        [
            cvs_path,
            "add",
            filename,
        ],
        cwd=workspace,
        timeout=60,
        env=cvs_environment(),
    )

    return {
        "ok": result["returncode"] == 0,
        "message": (
            result["stdout"]
            if result["returncode"] == 0
            else result["stderr"] or result["error"]
        ),
    }


def cvs_diff(workspace, filename):
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    result = run_command(
        [
            cvs_path,
            "diff",
            "-u",
            filename,
        ],
        cwd=workspace,
        timeout=60,
        env=cvs_environment(),
    )

    return {
        "ok": True,
        "message": result["stdout"] or result["stderr"],
    }


def cvs_commit(workspace, filename, message):
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    result = run_command(
        [
            cvs_path,
            "commit",
            "-m",
            message,
            filename,
        ],
        cwd=workspace,
        timeout=120,
        env=cvs_environment(),
    )

    return {
        "ok": result["returncode"] == 0,
        "message": (
            result["stdout"]
            if result["returncode"] == 0
            else result["stderr"] or result["error"]
        ),
    }


def cvs_log(workspace, filename):
    cvs_path = get_cvs_path()

    if not cvs_path:
        return {
            "ok": False,
            "message": "CVS executable was not found.",
        }

    result = run_command(
        [
            cvs_path,
            "log",
            filename,
        ],
        cwd=workspace,
        timeout=60,
        env=cvs_environment(),
    )

    return {
        "ok": result["returncode"] == 0,
        "message": (
            result["stdout"]
            if result["returncode"] == 0
            else result["stderr"] or result["error"]
        ),
    }


def cvs_prepare_workspace():
    if not st.session_state.cvs_workspace.strip():
        st.session_state.cvs_workspace = tempfile.mkdtemp(
            prefix="cvs_workspace_"
        )

    os.makedirs(
        st.session_state.cvs_workspace,
        exist_ok=True,
    )

    return st.session_state.cvs_workspace


def save_code_to_cvs_workspace():
    workspace = cvs_prepare_workspace()

    path = os.path.join(
        workspace,
        st.session_state.filename,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            st.session_state.terraform_code
        )

    return path


def cvs_validate_and_commit():
    if not cvs_is_available():
        return {
            "ok": False,
            "message": (
                "CVS is not installed on the machine "
                "running this application."
            ),
        }

    if not st.session_state.cvs_root.strip():
        return {
            "ok": False,
            "message": (
                "Enter the CVSROOT in the CVS Settings "
                "before using CVS."
            ),
        }

    if not st.session_state.cvs_module.strip():
        return {
            "ok": False,
            "message": (
                "Enter the CVS module name in CVS Settings."
            ),
        }

    workspace = cvs_prepare_workspace()

    checkout = cvs_checkout(
        st.session_state.cvs_module.strip(),
        workspace,
    )

    if not checkout["ok"]:
        return checkout

    st.session_state.terraform_code = st.session_state.terraform_code

    path = os.path.join(
        workspace,
        st.session_state.filename,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            st.session_state.terraform_code
        )

    update = cvs_update(workspace)

    if not update["ok"]:
        return update

    add_result = cvs_add(
        workspace,
        st.session_state.filename,
    )

    if not add_result["ok"]:
        message = add_result["message"].lower()

        if "already" not in message and "cvs/entries" not in message:
            return add_result

    result = run_checkov(
        st.session_state.terraform_code,
        st.session_state.filename,
    )

    st.session_state.checkov_result = result

    add_audit(
        "CVS validation",
        f"Checkov status: {result['status']}",
    )

    if result["status"] != "PASSED":
        return {
            "ok": False,
            "message": (
                "CVS commit blocked because Checkov "
                "reported security failures."
            ),
            "checkov": result,
        }

    commit = cvs_commit(
        workspace,
        st.session_state.filename,
        "Validated IaC security configuration",
    )

    if commit["ok"]:
        add_history(
            "Checkov validation passed and configuration committed to CVS."
        )

        add_audit(
            "CVS commit",
            "Successful CVS commit after Checkov validation.",
        )

    return {
        "ok": commit["ok"],
        "message": commit["message"],
        "checkov": result,
    }


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🔎 AI-IAC Validator</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="subtitle">
    Terraform/IaC security validation using Checkov,
    CVS version control and optional AI explanations.
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("⚙️ Configuration")

    st.session_state.settings_check = st.text_input(
        "Checkov checks",
        value=st.session_state.settings_check,
        help="Example: CKV_AWS_18,CKV_AWS_19",
    )

    st.session_state.settings_skip = st.text_input(
        "Skip Checkov checks",
        value=st.session_state.settings_skip,
        help="Example: CKV_AWS_999",
    )

    st.divider()

    st.header("📦 CVS Settings")

    st.session_state.cvs_root = st.text_input(
        "CVSROOT",
        value=st.session_state.cvs_root,
        placeholder="Example: /path/to/cvs/repository",
        type="default",
    )

    st.session_state.cvs_module = st.text_input(
        "CVS Module",
        value=st.session_state.cvs_module,
        placeholder="Example: iac-project",
    )

    st.session_state.cvs_username = st.text_input(
        "CVS Username",
        value=st.session_state.cvs_username,
    )

    st.session_state.cvs_workspace = st.text_input(
        "CVS Workspace",
        value=st.session_state.cvs_workspace,
        placeholder="Leave empty for temporary workspace",
    )

    if st.button(
        "🔍 Check CVS Installation",
        use_container_width=True,
    ):
        status = cvs_status()

        if status["ok"]:
            st.success("CVS is installed.")
            st.code(status["message"])
        else:
            st.error(status["message"])

    st.divider()

    st.info(
        "CVS is the version-control system. "
        "Checkov performs the security validation."
    )


# ============================================================
# DEMO BUTTONS
# ============================================================

st.subheader("🎯 Demonstration")

demo_col1, demo_col2 = st.columns(2)

with demo_col1:
    if st.button(
        "Load Unsafe Demo",
        use_container_width=True,
    ):
        st.session_state.terraform_code = UNSAFE_DEMO
        st.session_state.filename = "unsafe_demo.tf"
        st.session_state.checkov_result = None
        st.session_state.ai_explanation = ""
        st.session_state.suggested_code = ""
        st.rerun()

with demo_col2:
    if st.button(
        "Load Safe Demo",
        use_container_width=True,
    ):
        st.session_state.terraform_code = SAFE_DEMO
        st.session_state.filename = "safe_demo.tf"
        st.session_state.checkov_result = None
        st.session_state.ai_explanation = ""
        st.session_state.suggested_code = ""
        st.rerun()


# ============================================================
# UPLOAD
# ============================================================

uploaded = st.file_uploader(
    "Upload Terraform/IaC file",
    type=[
        "tf",
        "tfvars",
        "yaml",
        "yml",
        "json",
    ],
)

if uploaded is not None:

    try:
        uploaded_text = uploaded.read().decode(
            "utf-8",
            errors="replace",
        )

        st.session_state.terraform_code = uploaded_text
        st.session_state.filename = uploaded.name

        add_audit(
            "File upload",
            uploaded.name,
        )

    except Exception as exc:
        st.error(
            f"Could not read uploaded file: {exc}"
        )


# ============================================================
# CODE EDITOR
# ============================================================

st.subheader("📝 IaC Code")

st.session_state.terraform_code = st.text_area(
    "Terraform/IaC",
    value=st.session_state.terraform_code,
    height=420,
)

st.session_state.filename = st.text_input(
    "Filename",
    value=st.session_state.filename,
)


# ============================================================
# VALIDATION BUTTON
# ============================================================

col1, col2, col3 = st.columns(3)

with col1:
    run_validation = st.button(
        "🔎 Run Checkov",
        use_container_width=True,
    )

with col2:
    validate_cvs = st.button(
        "🔐 Validate Through CVS",
        use_container_width=True,
    )

with col3:
    create_correction = st.button(
        "🛠️ Suggest Correction",
        use_container_width=True,
    )


if run_validation:

    with st.spinner("Running Checkov..."):

        result = run_checkov(
            st.session_state.terraform_code,
            st.session_state.filename,
        )

    st.session_state.checkov_result = result

    add_audit(
        "Checkov validation",
        f"Status: {result['status']}",
    )

    add_history(
        f"Checkov validation: {result['status']}"
    )


if validate_cvs:

    with st.spinner(
        "CVS → Checkov validation → CVS commit..."
    ):

        result = cvs_validate_and_commit()

    if result["ok"]:
        st.success(
            "Checkov validation passed and the "
            "configuration was committed to CVS."
        )
    else:
        st.error(
            result["message"]
        )

    if result.get("checkov"):
        st.session_state.checkov_result = (
            result["checkov"]
        )


if create_correction:

    findings = []

    if st.session_state.checkov_result:
        findings = st.session_state.checkov_result.get(
            "findings",
            [],
        )

    corrected = generate_correction(
        st.session_state.terraform_code,
    )

    if corrected:

        st.session_state.suggested_code = corrected

        add_audit(
            "Correction generated",
            "Generated a restricted SSH example correction.",
        )

        st.success(
            "A suggested correction was generated."
        )

    elif findings:

        finding = next(
            (
                item
                for item in findings
                if item["status"] == "FAILED"
            ),
            findings[0],
        )

        st.session_state.ai_explanation = (
            get_ai_explanation(finding)
        )

        st.info(
            "An explanation was generated for the finding."
        )

    else:

        st.info(
            "Run Checkov first or use the unsafe demo."
        )


# ============================================================
# CHECKOV RESULTS
# ============================================================

result = st.session_state.checkov_result

if result:

    st.subheader("📊 Checkov Results")

    if result["status"] == "PASSED":

        st.markdown(
            '<div class="status-pass">'
            '✅ Validation PASSED — no failed checks '
            'were reported by Checkov.'
            '</div>',
            unsafe_allow_html=True,
        )

    elif result["status"] == "FAILED":

        st.markdown(
            '<div class="status-fail">'
            '❌ Validation FAILED — security/policy '
            'violations were detected.'
            '</div>',
            unsafe_allow_html=True,
        )

    else:

        st.markdown(
            '<div class="status-info">'
            '⚠️ Validation could not be completed.'
            '</div>',
            unsafe_allow_html=True,
        )

    if result["status"] == "ERROR":

        st.error(result["error"])

    else:

        m1, m2, m3 = st.columns(3)

        m1.metric(
            "Passed",
            result["passed"],
        )

        m2.metric(
            "Failed",
            result["failed"],
        )

        m3.metric(
            "Skipped",
            result["skipped"],
        )

        findings = result["findings"]

        if findings:

            st.subheader("Security Findings")

            table_rows = []

            for item in findings:
                table_rows.append(
                    {
                        "Status": item["status"],
                        "Check ID": item["check_id"],
                        "Check": item["check_name"],
                        "Severity": item["severity"],
                        "Resource": item["resource"],
                    }
                )

            st.dataframe(
                pd.DataFrame(table_rows),
                use_container_width=True,
            )

            failed = [
                item
                for item in findings
                if item["status"] == "FAILED"
            ]

            if failed:

                st.subheader(
                    "❌ Failed Security Checks"
                )

                for index, finding in enumerate(
                    failed,
                    start=1,
                ):

                    with st.expander(
                        f"{index}. {finding['check_id']} — {finding['check_name']}"
                    ):

                        st.write(
                            f"**Resource:** {finding['resource']}"
                        )

                        st.write(
                            f"**Severity:** {finding['severity']}"
                        )

                        if finding["file_line_range"]:
                            st.write(
                                f"**Lines:** {finding['file_line_range']}"
                            )

                        if finding["guideline"]:
                            st.write(
                                f"**Guideline:** {finding['guideline']}"
                            )

                        if finding["code_block"]:
                            st.code(
                                "\n".join(
                                    finding["code_block"]
                                ),
                                language="terraform",
                            )

                        if st.button(
                            f"Explain {finding['check_id']}",
                            key=f"explain_{index}",
                        ):

                            st.session_state.ai_explanation = (
                                get_ai_explanation(
                                    finding
                                )
                            )

                            st.rerun()


# ============================================================
# AI EXPLANATION
# ============================================================

if st.session_state.ai_explanation:

    st.subheader("🤖 AI Explanation")

    st.markdown(
        st.session_state.ai_explanation
    )


# ============================================================
# SUGGESTED CORRECTION
# ============================================================

if st.session_state.suggested_code:

    st.subheader("🛠️ Suggested Correction")

    st.code(
        st.session_state.suggested_code,
        language="terraform",
    )

    if st.button(
        "Use Suggested Correction",
        use_container_width=True,
    ):

        st.session_state.previous_code = (
            st.session_state.terraform_code
        )

        st.session_state.terraform_code = (
            st.session_state.suggested_code
        )

        st.session_state.suggested_code = ""

        add_audit(
            "Correction applied",
            "User applied suggested Terraform correction.",
        )

        st.success(
            "Correction applied. Run validation again."
        )

        st.rerun()


# ============================================================
# CVS OPERATIONS
# ============================================================

st.divider()

st.subheader("📦 CVS Version Control")

c1, c2, c3 = st.columns(3)

with c1:

    if st.button(
        "📥 CVS Checkout",
        use_container_width=True,
    ):

        if not st.session_state.cvs_root:
            st.error("Enter CVSROOT in the sidebar.")

        elif not st.session_state.cvs_module:
            st.error("Enter CVS Module in the sidebar.")

        else:

            workspace = cvs_prepare_workspace()

            result = cvs_checkout(
                st.session_state.cvs_module,
                workspace,
            )

            if result["ok"]:
                st.success("CVS checkout successful.")
                st.session_state.cvs_output = (
                    result["message"]
                )

                add_audit(
                    "CVS checkout",
                    st.session_state.cvs_module,
                )

            else:
                st.error(result["message"])


with c2:

    if st.button(
        "🔄 CVS Update",
        use_container_width=True,
    ):

        if not st.session_state.cvs_workspace:
            st.error(
                "Create or specify a CVS workspace first."
            )

        else:

            result = cvs_update(
                st.session_state.cvs_workspace
            )

            if result["ok"]:
                st.success("CVS update completed.")
                st.session_state.cvs_output = (
                    result["message"]
                )

            else:
                st.error(result["message"])


with c3:

    if st.button(
        "📜 CVS History",
        use_container_width=True,
    ):

        if not st.session_state.cvs_workspace:
            st.error(
                "Create or specify a CVS workspace first."
            )

        else:

            result = cvs_log(
                st.session_state.cvs_workspace,
                st.session_state.filename,
            )

            if result["ok"]:
                st.code(
                    result["message"],
                    language="text",
                )

            else:
                st.error(result["message"])


if st.session_state.cvs_output:

    with st.expander(
        "CVS Command Output",
        expanded=False,
    ):

        st.code(
            st.session_state.cvs_output,
            language="text",
        )


# ============================================================
# LOCAL AUDIT LOG
# ============================================================

st.divider()

st.subheader("📝 Application Audit Log")

if st.session_state.audit_log:

    st.dataframe(
        pd.DataFrame(
            st.session_state.audit_log
        ),
        use_container_width=True,
    )

else:

    st.info(
        "No application actions recorded yet."
    )


# ============================================================
# EXPORT RESULTS
# ============================================================

st.divider()

st.subheader("📄 Export Results")

if result and result.get("findings"):

    rows = []

    for finding in result["findings"]:

        rows.append(
            {
                "Timestamp": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "Filename": st.session_state.filename,
                "Status": finding["status"],
                "Check ID": finding["check_id"],
                "Check Name": finding["check_name"],
                "Severity": finding["severity"],
                "Resource": finding["resource"],
                "Guideline": finding["guideline"],
            }
        )

    df = pd.DataFrame(rows)

    csv_data = df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        "⬇️ Download Validation Report",
        data=csv_data,
        file_name="iac_validation_report.csv",
        mime="text/csv",
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "AI-IAC Validator | Terraform/IaC Security | "
    "Checkov | CVS Version Control"
)
