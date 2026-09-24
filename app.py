import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="AI-IAC Security Validator",
    page_icon="🛡️",
    layout="wide"
)


SAFE_DEMO = '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "safe_demo" {
  name        = "safe-demo"
  description = "Security group with restricted SSH access"

  ingress {
    description = "SSH from approved network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  egress {
    description = "Outbound access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''


UNSAFE_DEMO = '''terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "unsafe_demo" {
  name = "unsafe-demo"

  ingress {
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
'''


DEFAULT_POLICY = [
    {
        "id": "POLICY-SSH-001",
        "name": "No Public SSH",
        "description": "SSH must not be accessible from the public internet.",
        "severity": "HIGH",
        "type": "public_ssh"
    },
    {
        "id": "POLICY-SSH-002",
        "name": "SSH Port Must Be 22",
        "description": "SSH must use port 22.",
        "severity": "MEDIUM",
        "type": "ssh_port"
    },
    {
        "id": "POLICY-DESC-001",
        "name": "Security Group Needs Description",
        "description": "Every security group must contain a description.",
        "severity": "MEDIUM",
        "type": "security_group_description"
    }
]


if "policy" not in st.session_state:
    st.session_state.policy = DEFAULT_POLICY.copy()

if "terraform_code" not in st.session_state:
    st.session_state.terraform_code = SAFE_DEMO

if "source_type" not in st.session_state:
    st.session_state.source_type = "Safe Demo"

if "source_name" not in st.session_state:
    st.session_state.source_name = "safe_demo.tf"

if "editor_version" not in st.session_state:
    st.session_state.editor_version = 0

if "validation_result" not in st.session_state:
    st.session_state.validation_result = None

if "suggested_code" not in st.session_state:
    st.session_state.suggested_code = ""

if "history" not in st.session_state:
    st.session_state.history = []

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "last_uploaded_file" not in st.session_state:
    st.session_state.last_uploaded_file = ""

if "cvs_initialized" not in st.session_state:
    st.session_state.cvs_initialized = False

if "cvs_repository" not in st.session_state:
    st.session_state.cvs_repository = ""

if "cvs_module" not in st.session_state:
    st.session_state.cvs_module = ""

if "cvs_workspace" not in st.session_state:
    st.session_state.cvs_workspace = ""


def add_audit(action, details=""):
    st.session_state.audit_log.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "details": details
        }
    )


def load_terraform(code, source_type, filename):
    st.session_state.terraform_code = code
    st.session_state.source_type = source_type
    st.session_state.source_name = filename
    st.session_state.validation_result = None
    st.session_state.suggested_code = ""
    st.session_state.editor_version += 1


def extract_blocks(code, block_name):
    blocks = []

    pattern = re.compile(
        rf"(?is)\b{re.escape(block_name)}\s*\{{"
    )

    for match in pattern.finditer(code):
        start = match.start()
        position = match.end()
        depth = 1

        while position < len(code) and depth > 0:
            if code[position] == "{":
                depth += 1
            elif code[position] == "}":
                depth -= 1

            position += 1

        if depth == 0:
            blocks.append(
                code[start:position]
            )

    return blocks


def extract_security_group_blocks(code):
    blocks = []

    pattern = re.compile(
        r'(?is)resource\s+"aws_security_group"\s+"[^"]+"\s*\{'
    )

    for match in pattern.finditer(code):
        start = match.start()
        position = match.end()
        depth = 1

        while position < len(code) and depth > 0:
            if code[position] == "{":
                depth += 1
            elif code[position] == "}":
                depth -= 1

            position += 1

        if depth == 0:
            blocks.append(
                code[start:position]
            )

    return blocks


def check_public_ssh(code):
    ingress_blocks = extract_blocks(
        code,
        "ingress"
    )

    for block in ingress_blocks:
        from_match = re.search(
            r"from_port\s*=\s*(\d+)",
            block
        )

        to_match = re.search(
            r"to_port\s*=\s*(\d+)",
            block
        )

        cidr_match = re.search(
            r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            block
        )

        if not from_match or not to_match:
            continue

        if not cidr_match:
            continue

        from_port = int(
            from_match.group(1)
        )

        to_port = int(
            to_match.group(1)
        )

        if from_port <= 22 <= to_port:
            return True

    return False


def check_ssh_port(code):
    ingress_blocks = extract_blocks(
        code,
        "ingress"
    )

    for block in ingress_blocks:
        from_match = re.search(
            r"from_port\s*=\s*(\d+)",
            block
        )

        to_match = re.search(
            r"to_port\s*=\s*(\d+)",
            block
        )

        if not from_match or not to_match:
            continue

        from_port = int(
            from_match.group(1)
        )

        to_port = int(
            to_match.group(1)
        )

        if from_port == 22 or to_port == 22:
            if from_port != 22 or to_port != 22:
                return False

    return True


def check_security_group_description(code):
    blocks = extract_security_group_blocks(
        code
    )

    for block in blocks:
        if not re.search(
            r"\bdescription\s*=",
            block
        ):
            return False

    return True


def run_company_policy(code):
    results = []

    for rule in st.session_state.policy:
        rule_type = rule.get(
            "type",
            ""
        )

        passed = True
        reason = ""

        if rule_type == "public_ssh":
            passed = not check_public_ssh(
                code
            )

            reason = (
                "No public SSH access detected."
                if passed
                else "SSH port 22 is exposed to 0.0.0.0/0."
            )

        elif rule_type == "ssh_port":
            passed = check_ssh_port(
                code
            )

            reason = (
                "SSH uses port 22."
                if passed
                else "SSH configuration does not use port 22."
            )

        elif rule_type == "security_group_description":
            passed = check_security_group_description(
                code
            )

            reason = (
                "Security group has a description."
                if passed
                else "Security group is missing a description."
            )

        elif rule_type == "forbidden_text":
            value = rule.get(
                "forbidden_text",
                ""
            )

            passed = value not in code

            reason = (
                "Forbidden configuration was not found."
                if passed
                else f"Forbidden configuration found: {value}"
            )

        elif rule_type == "required_text":
            value = rule.get(
                "required_text",
                ""
            )

            passed = value in code

            reason = (
                "Required configuration was found."
                if passed
                else f"Required configuration missing: {value}"
            )

        elif rule_type == "regex":
            pattern = rule.get(
                "regex",
                ""
            )

            try:
                passed = bool(
                    re.search(
                        pattern,
                        code,
                        re.MULTILINE
                    )
                )
            except re.error:
                passed = False

            reason = (
                "Required pattern was found."
                if passed
                else "Required pattern was not found."
            )

        else:
            results.append(
                {
                    "id": rule.get(
                        "id",
                        "UNKNOWN"
                    ),
                    "name": rule.get(
                        "name",
                        "Unknown Rule"
                    ),
                    "severity": rule.get(
                        "severity",
                        "MEDIUM"
                    ),
                    "source": "Company Policy",
                    "status": "SKIPPED",
                    "reason": "Unsupported policy rule type."
                }
            )

            continue

        results.append(
            {
                "id": rule.get(
                    "id",
                    "UNKNOWN"
                ),
                "name": rule.get(
                    "name",
                    "Security Policy Rule"
                ),
                "severity": rule.get(
                    "severity",
                    "MEDIUM"
                ),
                "source": "Company Policy",
                "status": (
                    "PASSED"
                    if passed
                    else "FAILED"
                ),
                "reason": reason
            }
        )

    return results


def run_checkov(code):
    if shutil.which("checkov") is None:
        return [
            {
                "id": "CHECKOV-NOT-INSTALLED",
                "name": "Checkov",
                "severity": "INFO",
                "source": "Checkov",
                "status": "SKIPPED",
                "reason": "Checkov is not installed."
            }
        ]

    temp_dir = tempfile.mkdtemp(
        prefix="iac_check_"
    )

    tf_file = os.path.join(
        temp_dir,
        "main.tf"
    )

    try:
        with open(
            tf_file,
            "w",
            encoding="utf-8"
        ) as file:
            file.write(code)

        command = [
            "checkov",
            "-d",
            temp_dir,
            "--framework",
            "terraform",
            "--check",
            "CKV_AWS_24",
            "--output",
            "json",
            "--quiet"
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = process.stdout.strip()

        if not output:
            if process.returncode == 0:
                return [
                    {
                        "id": "CKV_AWS_24",
                        "name": "No Public SSH Access",
                        "severity": "HIGH",
                        "source": "Checkov",
                        "status": "PASSED",
                        "reason": "Checkov passed the configured SSH security check."
                    }
                ]

            return [
                {
                    "id": "CKV_AWS_24",
                    "name": "No Public SSH Access",
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "FAILED",
                    "reason": process.stderr.strip()
                    or
                    "Checkov failed the security check."
                }
            ]

        try:
            data = json.loads(
                output
            )
        except json.JSONDecodeError:
            return [
                {
                    "id": "CHECKOV-OUTPUT",
                    "name": "Checkov Result",
                    "severity": "INFO",
                    "source": "Checkov",
                    "status": "SKIPPED",
                    "reason": "Checkov output could not be parsed."
                }
            ]

        check_results = data.get(
            "results",
            {}
        )

        failed_checks = check_results.get(
            "failed_checks",
            []
        )

        passed_checks = check_results.get(
            "passed_checks",
            []
        )

        results = []

        for item in failed_checks:
            results.append(
                {
                    "id": item.get(
                        "check_id",
                        "CHECKOV"
                    ),
                    "name": item.get(
                        "check_name",
                        "Checkov Security Check"
                    ),
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "FAILED",
                    "reason": item.get(
                        "check_name",
                        "Checkov detected a security issue."
                    )
                }
            )

        if not failed_checks:
            results.append(
                {
                    "id": "CKV_AWS_24",
                    "name": "No Public SSH Access",
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "PASSED",
                    "reason": (
                        "Checkov passed the configured SSH security check."
                    )
                }
            )

        return results

    except subprocess.TimeoutExpired:
        return [
            {
                "id": "CHECKOV-TIMEOUT",
                "name": "Checkov",
                "severity": "INFO",
                "source": "Checkov",
                "status": "SKIPPED",
                "reason": "Checkov execution timed out."
            }
        ]

    except Exception as error:
        return [
            {
                "id": "CHECKOV-ERROR",
                "name": "Checkov",
                "severity": "INFO",
                "source": "Checkov",
                "status": "SKIPPED",
                "reason": str(error)
            }
        ]

    finally:
        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )


def validate_terraform(code):
    policy_results = run_company_policy(
        code
    )

    checkov_results = run_checkov(
        code
    )

    results = (
        policy_results
        +
        checkov_results
    )

    passed = sum(
        1
        for item in results
        if item["status"] == "PASSED"
    )

    failed = sum(
        1
        for item in results
        if item["status"] == "FAILED"
    )

    skipped = sum(
        1
        for item in results
        if item["status"] == "SKIPPED"
    )

    return {
        "results": results,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": len(results),
        "overall_passed": failed == 0,
        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }


def generate_correction(code, failed_results):
    corrected = code

    failed_ids = {
        item["id"]
        for item in failed_results
    }

    public_ssh_failed = (
        "POLICY-SSH-001" in failed_ids
        or
        "CKV_AWS_24" in failed_ids
    )

    description_failed = (
        "POLICY-DESC-001" in failed_ids
    )

    ssh_port_failed = (
        "POLICY-SSH-002" in failed_ids
    )

    if public_ssh_failed:
        corrected = re.sub(
            r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            'cidr_blocks = ["10.0.0.0/24"]',
            corrected
        )

    if ssh_port_failed:
        corrected = re.sub(
            r"from_port\s*=\s*\d+",
            "from_port   = 22",
            corrected
        )

        corrected = re.sub(
            r"to_port\s*=\s*\d+",
            "to_port     = 22",
            corrected
        )

    if description_failed:
        pattern = (
            r'(resource\s+"aws_security_group"\s+"[^"]+"\s*\{\s*'
            r'name\s*=\s*"[^"]+"\s*)'
        )

        replacement = (
            r'\1\n'
            r'  description = "Security group corrected by security remediation"\n'
        )

        corrected = re.sub(
            pattern,
            replacement,
            corrected,
            count=1
        )

    return corrected


def policy_section():
    st.subheader("1. Company Security Policy")

    st.write(
        "Terraform is checked against organization-defined security rules."
    )

    st.dataframe(
        pd.DataFrame(
            st.session_state.policy
        ),
        use_container_width=True,
        hide_index=True
    )

    with st.expander(
        "✏️ Edit Complete Policy"
    ):
        policy_json = st.text_area(
            "Policy JSON",
            value=json.dumps(
                st.session_state.policy,
                indent=2
            ),
            height=300
        )

        if st.button(
            "💾 SAVE POLICY"
        ):
            try:
                new_policy = json.loads(
                    policy_json
                )

                if not isinstance(
                    new_policy,
                    list
                ):
                    st.error(
                        "Policy must be a JSON list."
                    )
                else:
                    st.session_state.policy = (
                        new_policy
                    )

                    add_audit(
                        "Company Policy Updated"
                    )

                    st.success(
                        "Company security policy updated."
                    )

                    st.rerun()

            except Exception as error:
                st.error(
                    f"Invalid policy JSON: {error}"
                )

    with st.expander(
        "➕ Add New Policy Rule"
    ):
        rule_id = st.text_input(
            "Rule ID",
            placeholder="POLICY-CUSTOM-001"
        )

        rule_name = st.text_input(
            "Rule Name"
        )

        rule_description = st.text_input(
            "Rule Description"
        )

        severity = st.selectbox(
            "Severity",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]
        )

        rule_type = st.selectbox(
            "Rule Type",
            [
                "public_ssh",
                "ssh_port",
                "security_group_description",
                "forbidden_text",
                "required_text",
                "regex"
            ]
        )

        rule_value = st.text_input(
            "Rule Value"
        )

        if st.button(
            "➕ ADD RULE"
        ):
            if not rule_id or not rule_name:
                st.error(
                    "Rule ID and Rule Name are required."
                )
            else:
                new_rule = {
                    "id": rule_id,
                    "name": rule_name,
                    "description": rule_description,
                    "severity": severity,
                    "type": rule_type
                }

                if rule_type == "forbidden_text":
                    new_rule["forbidden_text"] = rule_value

                if rule_type == "required_text":
                    new_rule["required_text"] = rule_value

                if rule_type == "regex":
                    new_rule["regex"] = rule_value

                st.session_state.policy.append(
                    new_rule
                )

                add_audit(
                    "Policy Rule Added",
                    rule_id
                )

                st.success(
                    "New policy rule added."
                )

                st.rerun()


def choose_terraform():
    st.subheader("2. Choose Terraform")

    st.write(
        "Choose a safe example, unsafe example, or upload your own Terraform."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            "🟢 SAFE DEMO",
            use_container_width=True
        ):
            load_terraform(
                SAFE_DEMO,
                "Safe Demo",
                "safe_demo.tf"
            )

            add_audit(
                "Safe Demo Selected"
            )

            st.rerun()

    with col2:
        if st.button(
            "🔴 UNSAFE DEMO",
            use_container_width=True
        ):
            load_terraform(
                UNSAFE_DEMO,
                "Unsafe Demo",
                "unsafe_demo.tf"
            )

            add_audit(
                "Unsafe Demo Selected"
            )

            st.rerun()

    with col3:
        uploaded_file = st.file_uploader(
            "📤 Upload Your Terraform",
            type=["tf"],
            key="terraform_upload"
        )

        if uploaded_file is not None:
            file_signature = (
                f"{uploaded_file.name}-"
                f"{uploaded_file.size}"
            )

            if (
                file_signature
                !=
                st.session_state.last_uploaded_file
            ):
                try:
                    uploaded_code = (
                        uploaded_file
                        .getvalue()
                        .decode("utf-8")
                    )

                    load_terraform(
                        uploaded_code,
                        "Uploaded Terraform",
                        uploaded_file.name
                    )

                    st.session_state.last_uploaded_file = (
                        file_signature
                    )

                    add_audit(
                        "Terraform Uploaded",
                        uploaded_file.name
                    )

                    st.rerun()

                except Exception as error:
                    st.error(
                        f"Could not read Terraform file: {error}"
                    )

    st.info(
        f"Current source: {st.session_state.source_type}"
    )

    filename_key = (
        f"filename_{st.session_state.editor_version}"
    )

    if filename_key not in st.session_state:
        st.session_state[filename_key] = (
            st.session_state.source_name
        )

    st.text_input(
        "Terraform filename",
        key=filename_key
    )

    st.session_state.source_name = (
        st.session_state[filename_key]
    )

    editor_key = (
        f"terraform_editor_{st.session_state.editor_version}"
    )

    if editor_key not in st.session_state:
        st.session_state[editor_key] = (
            st.session_state.terraform_code
        )

    st.text_area(
        "Terraform Code",
        height=430,
        key=editor_key
    )

    st.session_state.terraform_code = (
        st.session_state[editor_key]
    )

    if st.button(
        "🔄 VALIDATE TERRAFORM",
        type="primary",
        use_container_width=True
    ):
        result = validate_terraform(
            st.session_state.terraform_code
        )

        st.session_state.validation_result = result
        st.session_state.suggested_code = ""

        st.session_state.history.insert(
            0,
            {
                "time": result["time"],
                "source": st.session_state.source_name,
                "status": (
                    "PASSED"
                    if result["overall_passed"]
                    else "FAILED"
                ),
                "passed": result["passed"],
                "failed": result["failed"],
                "skipped": result["skipped"],
                "total": result["total"]
            }
        )

        add_audit(
            "Terraform Validated",
            (
                f'{st.session_state.source_name}: '
                f'{result["passed"]} passed, '
                f'{result["failed"]} failed'
            )
        )

        st.rerun()


def show_results():
    result = st.session_state.validation_result

    if result is None:
        st.info(
            "Validate Terraform to see security results."
        )
        return

    st.subheader("3. Validation Results")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "PASSED",
        result["passed"]
    )

    c2.metric(
        "FAILED",
        result["failed"]
    )

    c3.metric(
        "SKIPPED",
        result["skipped"]
    )

    c4.metric(
        "TOTAL",
        result["total"]
    )

    if result["overall_passed"]:
        st.success(
            "✅ ALL CHECKS PASSED"
        )

        st.write(
            "The Terraform configuration passed the configured company policy and security validation."
        )

        st.success(
            "No remediation is required."
        )

        return

    st.error(
        f'❌ VALIDATION FAILED — {result["failed"]} finding(s)'
    )

    results_df = pd.DataFrame(
        result["results"]
    )

    st.dataframe(
        results_df,
        use_container_width=True,
        hide_index=True
    )

    failed_results = [
        item
        for item in result["results"]
        if item["status"] == "FAILED"
    ]

    st.subheader("4. AI Remediation")

    st.warning(
        "Security findings were detected. Generate a corrected Terraform configuration and revalidate it."
    )

    if st.button(
        "🤖 GENERATE AI CORRECTION",
        type="primary",
        use_container_width=True
    ):
        st.session_state.suggested_code = (
            generate_correction(
                st.session_state.terraform_code,
                failed_results
            )
        )

        add_audit(
            "AI Correction Generated",
            f"{len(failed_results)} finding(s)"
        )

        st.rerun()

    if st.session_state.suggested_code:
        st.markdown(
            "### Suggested Corrected Terraform"
        )

        st.code(
            st.session_state.suggested_code,
            language="hcl"
        )

        st.info(
            "Review the generated correction before applying it."
        )

        if st.button(
            "✅ APPLY CORRECTED CODE",
            use_container_width=True
        ):
            st.session_state.terraform_code = (
                st.session_state.suggested_code
            )

            st.session_state.editor_version += 1
            st.session_state.validation_result = None
            st.session_state.suggested_code = ""

            add_audit(
                "Corrected Terraform Applied"
            )

            st.success(
                "Corrected Terraform applied. Revalidate it now."
            )

            st.rerun()


def run_cvs(command, cwd=None):
    if shutil.which("cvs") is None:
        return False, "CVS is not installed."

    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = (
            process.stdout
            + "\n"
            + process.stderr
        ).strip()

        return (
            process.returncode == 0,
            output
        )

    except subprocess.TimeoutExpired:
        return False, "CVS command timed out."

    except Exception as error:
        return False, str(error)


def initialize_demo_cvs():
    if shutil.which("cvs") is None:
        return False, "CVS is not installed."

    try:
        base_directory = tempfile.mkdtemp(
            prefix="ai_iac_cvs_"
        )

        repository = os.path.join(
            base_directory,
            "repository"
        )

        seed_directory = os.path.join(
            base_directory,
            "seed"
        )

        workspace_parent = os.path.join(
            base_directory,
            "workspace"
        )

        os.makedirs(
            repository,
            exist_ok=True
        )

        os.makedirs(
            seed_directory,
            exist_ok=True
        )

        os.makedirs(
            workspace_parent,
            exist_ok=True
        )

        init_success, init_output = run_cvs(
            [
                "cvs",
                "-d",
                repository,
                "init"
            ]
        )

        if not init_success:
            return False, init_output

        filename = os.path.basename(
            st.session_state.source_name
        )

        if not filename.endswith(".tf"):
            filename = "main.tf"

        seed_file = os.path.join(
            seed_directory,
            filename
        )

        with open(
            seed_file,
            "w",
            encoding="utf-8"
        ) as file:
            file.write(
                st.session_state.terraform_code
            )

        module_name = "terraform-project"

        import_success, import_output = run_cvs(
            [
                "cvs",
                "-d",
                repository,
                "import",
                "-m",
                "Initial Terraform version",
                module_name,
                "AI-IAC",
                "START"
            ],
            seed_directory
        )

        if not import_success:
            return False, import_output

        checkout_success, checkout_output = run_cvs(
            [
                "cvs",
                "-d",
                repository,
                "checkout",
                "-d",
                module_name,
                module_name
            ],
            workspace_parent
        )

        if not checkout_success:
            return False, checkout_output

        workspace = os.path.join(
            workspace_parent,
            module_name
        )

        st.session_state.cvs_repository = repository
        st.session_state.cvs_module = module_name
        st.session_state.cvs_workspace = workspace
        st.session_state.cvs_initialized = True

        add_audit(
            "Demo CVS Repository Initialized",
            f"Module: {module_name}"
        )

        return True, (
            "Demo CVS repository initialized successfully.\n\n"
            f"CVSROOT: {repository}\n"
            f"Module: {module_name}\n"
            f"Workspace: {workspace}"
        )

    except Exception as error:
        return False, str(error)


def cvs_section():
    st.subheader("5. CVS Source Control")

    st.write(
        "CVS provides version control for Terraform. "
        "The system validates Terraform before allowing a CVS commit."
    )

    if shutil.which("cvs") is not None:
        st.success(
            "✅ CVS is installed and available."
        )
    else:
        st.error(
            "❌ CVS is not installed."
        )

    st.markdown(
        "### 5.1 Initialize Demo CVS Repository"
    )

    st.write(
        "This creates a temporary CVS repository for the demonstration."
    )

    if st.button(
        "📦 INITIALIZE DEMO CVS",
        use_container_width=True
    ):
        success, output = initialize_demo_cvs()

        if success:
            st.success(
                "✅ Demo CVS repository initialized."
            )
        else:
            st.error(
                "❌ CVS initialization failed."
            )

        st.code(output)

    if not st.session_state.cvs_initialized:
        st.info(
            "Initialize the demo CVS repository before using CVS operations."
        )
        return

    st.markdown(
        "### 5.2 CVS Repository"
    )

    st.text_input(
        "CVSROOT",
        value=st.session_state.cvs_repository,
        disabled=True
    )

    st.text_input(
        "CVS Module",
        value=st.session_state.cvs_module,
        disabled=True
    )

    st.text_input(
        "CVS Workspace",
        value=st.session_state.cvs_workspace,
        disabled=True
    )

    st.success(
        "CVS repository is ready."
    )

    st.markdown(
        "### 5.3 CVS Operations"
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            "📥 CVS CHECKOUT",
            use_container_width=True
        ):
            parent_directory = os.path.dirname(
                st.session_state.cvs_workspace
            )

            if os.path.exists(
                st.session_state.cvs_workspace
            ):
                shutil.rmtree(
                    st.session_state.cvs_workspace
                )

            success, output = run_cvs(
                [
                    "cvs",
                    "-d",
                    st.session_state.cvs_repository,
                    "checkout",
                    "-d",
                    st.session_state.cvs_module,
                    st.session_state.cvs_module
                ],
                parent_directory
            )

            if success:
                st.success(
                    "✅ CVS checkout completed."
                )
            else:
                st.error(
                    "❌ CVS checkout failed."
                )

            st.code(output)

    with col2:
        if st.button(
            "🔄 CVS UPDATE",
            use_container_width=True
        ):
            success, output = run_cvs(
                [
                    "cvs",
                    "update",
                    "-dP"
                ],
                st.session_state.cvs_workspace
            )

            if success:
                st.success(
                    "✅ CVS update completed."
                )
            else:
                st.error(
                    "❌ CVS update failed."
                )

            st.code(output)

    with col3:
        if st.button(
            "🔎 CVS DIFF",
            use_container_width=True
        ):
            success, output = run_cvs(
                [
                    "cvs",
                    "diff"
                ],
                st.session_state.cvs_workspace
            )

            if output:
                st.code(output)
            else:
                st.success(
                    "No differences found."
                )

    st.markdown(
        "### 5.4 Security-Gated CVS Commit"
    )

    st.write(
        "The commit is allowed only when the current Terraform passes validation."
    )

    commit_message = st.text_input(
        "CVS Commit Message",
        value="Security validated Terraform configuration"
    )

    if st.button(
        "🔐 VALIDATE + CVS COMMIT",
        type="primary",
        use_container_width=True
    ):
        validation = validate_terraform(
            st.session_state.terraform_code
        )

        st.session_state.validation_result = validation

        if not validation["overall_passed"]:
            st.error(
                "🚫 CVS COMMIT BLOCKED"
            )

            st.write(
                "Security validation failed. Fix the Terraform before committing it to CVS."
            )

            failed_items = [
                item
                for item in validation["results"]
                if item["status"] == "FAILED"
            ]

            if failed_items:
                st.dataframe(
                    pd.DataFrame(
                        failed_items
                    ),
                    use_container_width=True,
                    hide_index=True
                )

            add_audit(
                "CVS Commit Blocked",
                f'{validation["failed"]} finding(s)'
            )

            st.rerun()

        filename = os.path.basename(
            st.session_state.source_name
        )

        if not filename.endswith(".tf"):
            filename = "main.tf"

        file_path = os.path.join(
            st.session_state.cvs_workspace,
            filename
        )

        try:
            os.makedirs(
                st.session_state.cvs_workspace,
                exist_ok=True
            )

            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as file:
                file.write(
                    st.session_state.terraform_code
                )

            status_success, status_output = run_cvs(
                [
                    "cvs",
                    "status",
                    filename
                ],
                st.session_state.cvs_workspace
            )

            needs_add = (
                f"? {filename}" in status_output
                or
                "Unknown" in status_output
            )

            add_output = ""

            if needs_add:
                add_success, add_output = run_cvs(
                    [
                        "cvs",
                        "add",
                        filename
                    ],
                    st.session_state.cvs_workspace
                )

                if not add_success:
                    st.error(
                        "❌ CVS could not add the Terraform file."
                    )

                    st.code(
                        add_output
                    )

                    add_audit(
                        "CVS Add Failed",
                        filename
                    )

                    return

            commit_success, commit_output = run_cvs(
                [
                    "cvs",
                    "commit",
                    "-m",
                    commit_message,
                    filename
                ],
                st.session_state.cvs_workspace
            )

            if commit_success:
                st.success(
                    "✅ VALIDATION PASSED — CVS COMMIT SUCCESSFUL"
                )

                st.write(
                    "The Terraform passed security validation and was committed to CVS."
                )

                add_audit(
                    "CVS Commit Successful",
                    commit_message
                )

            else:
                st.error(
                    "❌ Validation passed, but CVS commit failed."
                )

                st.code(
                    commit_output
                )

                add_audit(
                    "CVS Commit Failed",
                    commit_output
                )

        except Exception as error:
            st.error(
                f"CVS operation failed: {error}"
            )


def history_section():
    st.subheader("6. Validation History")

    if not st.session_state.history:
        st.info(
            "No validation history yet."
        )
        return

    st.dataframe(
        pd.DataFrame(
            st.session_state.history
        ),
        use_container_width=True,
        hide_index=True
    )


def audit_section():
    st.subheader("7. Audit Log")

    if not st.session_state.audit_log:
        st.info(
            "No audit events yet."
        )
        return

    st.dataframe(
        pd.DataFrame(
            st.session_state.audit_log
        ),
        use_container_width=True,
        hide_index=True
    )


st.title(
    "🛡️ AI-IAC Security Configuration Validator"
)

st.markdown(
    """
### Terraform Security Validation and Remediation

**Terraform → Company Policy → Checkov → Findings → Remediation → Revalidation → CVS**
"""
)

st.divider()

policy_section()

st.divider()

choose_terraform()

st.divider()

show_results()

st.divider()

cvs_section()

st.divider()

history_section()

st.divider()

audit_section()
