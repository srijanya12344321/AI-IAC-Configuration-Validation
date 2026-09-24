import os
import re
import json
import shutil
import tempfile
import subprocess
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

if "source_name" not in st.session_state:
    st.session_state.source_name = "safe_demo.tf"

if "source_type" not in st.session_state:
    st.session_state.source_type = "Safe Demo"

if "validation_result" not in st.session_state:
    st.session_state.validation_result = None

if "suggested_code" not in st.session_state:
    st.session_state.suggested_code = ""

if "history" not in st.session_state:
    st.session_state.history = []

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "uploaded_file_name" not in st.session_state:
    st.session_state.uploaded_file_name = ""


def audit(action, details=""):
    st.session_state.audit_log.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "details": details
        }
    )


def extract_ingress_blocks(code):
    blocks = []

    pattern = re.compile(
        r'(?is)\bingress\s*\{'
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
    blocks = extract_ingress_blocks(code)

    for block in blocks:
        from_match = re.search(
            r'from_port\s*=\s*(\d+)',
            block
        )

        to_match = re.search(
            r'to_port\s*=\s*(\d+)',
            block
        )

        public = re.search(
            r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            block
        )

        if from_match and to_match and public:
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
    blocks = extract_ingress_blocks(code)

    ssh_found = False

    for block in blocks:
        from_match = re.search(
            r'from_port\s*=\s*(\d+)',
            block
        )

        to_match = re.search(
            r'to_port\s*=\s*(\d+)',
            block
        )

        if from_match and to_match:
            from_port = int(
                from_match.group(1)
            )

            to_port = int(
                to_match.group(1)
            )

            if from_port == 22 or to_port == 22:
                ssh_found = True

                if from_port != 22 or to_port != 22:
                    return False

    return True


def check_security_group_description(code):
    blocks = extract_security_group_blocks(code)

    for block in blocks:
        if not re.search(
            r'\bdescription\s*=',
            block
        ):
            return False

    return True


def run_policy(code):
    results = []

    for rule in st.session_state.policy:
        rule_type = rule.get(
            "type",
            ""
        )

        passed = True
        reason = ""

        if rule_type == "public_ssh":
            passed = not check_public_ssh(code)

            reason = (
                "No public SSH access detected."
                if passed
                else "SSH port 22 is exposed to 0.0.0.0/0."
            )

        elif rule_type == "ssh_port":
            passed = check_ssh_port(code)

            reason = (
                "SSH uses port 22."
                if passed
                else "SSH is configured with an invalid port."
            )

        elif rule_type == "security_group_description":
            passed = check_security_group_description(
                code
            )

            reason = (
                "Security group contains a description."
                if passed
                else "Security group is missing a description."
            )

        elif rule_type == "forbidden_text":
            text = rule.get(
                "forbidden_text",
                ""
            )

            passed = text not in code

            reason = (
                "Forbidden configuration not found."
                if passed
                else f"Forbidden configuration found: {text}"
            )

        elif rule_type == "required_text":
            text = rule.get(
                "required_text",
                ""
            )

            passed = text in code

            reason = (
                "Required configuration found."
                if passed
                else f"Required configuration missing: {text}"
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
                "Required pattern found."
                if passed
                else "Required pattern not found."
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
                    "reason": "Unsupported rule type."
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
        prefix="iac_validation_"
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
            return [
                {
                    "id": "CKV_AWS_24",
                    "name": "Public SSH Check",
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": (
                        "PASSED"
                        if process.returncode == 0
                        else "FAILED"
                    ),
                    "reason": (
                        "Checkov passed the public SSH check."
                        if process.returncode == 0
                        else process.stderr.strip()
                    )
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

        failed_checks = data.get(
            "results",
            {}
        ).get(
            "failed_checks",
            []
        )

        passed_checks = data.get(
            "results",
            {}
        ).get(
            "passed_checks",
            []
        )

        results = []

        for check in failed_checks:
            results.append(
                {
                    "id": check.get(
                        "check_id",
                        "CHECKOV"
                    ),
                    "name": check.get(
                        "check_name",
                        "Checkov Security Check"
                    ),
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "FAILED",
                    "reason": check.get(
                        "check_name",
                        "Checkov detected a security issue."
                    )
                }
            )

        if not failed_checks:
            results.append(
                {
                    "id": "CKV_AWS_24",
                    "name": "Public SSH Check",
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "PASSED",
                    "reason": "Checkov passed the configured security check."
                }
            )

        return results

    except Exception as error:
        return [
            {
                "id": "CHECKOV-ERROR",
                "name": "Checkov Execution",
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


def validate(code):
    policy_results = run_policy(
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


def generate_correction(code, results):
    corrected = code

    failed_ids = {
        item["id"]
        for item in results
        if item["status"] == "FAILED"
    }

    public_ssh_problem = (
        "POLICY-SSH-001" in failed_ids
        or
        "CKV_AWS_24" in failed_ids
    )

    if public_ssh_problem:
        corrected = re.sub(
            r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            'cidr_blocks = ["10.0.0.0/24"]',
            corrected
        )

    if "POLICY-SSH-002" in failed_ids:
        corrected = re.sub(
            r'from_port\s*=\s*\d+',
            'from_port   = 22',
            corrected
        )

        corrected = re.sub(
            r'to_port\s*=\s*\d+',
            'to_port     = 22',
            corrected
        )

    if "POLICY-DESC-001" in failed_ids:
        blocks = extract_security_group_blocks(
            corrected
        )

        if blocks:
            first_block = blocks[0]

            if not re.search(
                r'\bdescription\s*=',
                first_block
            ):
                corrected = re.sub(
                    r'(resource\s+"aws_security_group"\s+"[^"]+"\s*\{\s*name\s*=\s*"[^"]+"\s*)',
                    r'\1\n  description = "Security group corrected by security remediation"\n',
                    corrected,
                    count=1
                )

    if corrected == code:
        corrected = code.replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/24"]'
        )

        if not re.search(
            r'resource\s+"aws_security_group"',
            corrected
        ):
            corrected = code

    return corrected


def choose_terraform():
    st.subheader("2. Choose Terraform")

    st.write(
        "Use a built-in demonstration or upload your own Terraform file."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            "🟢 SAFE DEMO",
            use_container_width=True
        ):
            st.session_state.source_type = "Safe Demo"
            st.session_state.source_name = "safe_demo.tf"
            st.session_state.terraform_code = SAFE_DEMO
            st.session_state.validation_result = None
            st.session_state.suggested_code = ""

            audit(
                "Safe Demo Selected"
            )

            st.rerun()

    with col2:
        if st.button(
            "🔴 UNSAFE DEMO",
            use_container_width=True
        ):
            st.session_state.source_type = "Unsafe Demo"
            st.session_state.source_name = "unsafe_demo.tf"
            st.session_state.terraform_code = UNSAFE_DEMO
            st.session_state.validation_result = None
            st.session_state.suggested_code = ""

            audit(
                "Unsafe Demo Selected"
            )

            st.rerun()

    with col3:
        uploaded = st.file_uploader(
            "📤 Upload .tf",
            type=["tf"],
            key="terraform_upload"
        )

        if uploaded is not None:
            try:
                content = uploaded.getvalue().decode(
                    "utf-8"
                )

                st.session_state.source_type = (
                    "Uploaded Terraform"
                )

                st.session_state.source_name = (
                    uploaded.name
                )

                st.session_state.uploaded_file_name = (
                    uploaded.name
                )

                st.session_state.terraform_code = (
                    content
                )

                st.session_state.validation_result = None
                st.session_state.suggested_code = ""

                audit(
                    "Terraform Uploaded",
                    uploaded.name
                )

            except Exception as error:
                st.error(
                    f"Could not read Terraform file: {error}"
                )

    st.info(
        f"Current Terraform source: {st.session_state.source_type}"
    )

    st.text_input(
        "Terraform filename",
        value=st.session_state.source_name,
        key="filename_box"
    )

    st.session_state.source_name = (
        st.session_state.filename_box
    )

    edited_code = st.text_area(
        "Terraform Code",
        value=st.session_state.terraform_code,
        height=430,
        key="terraform_code_editor"
    )

    st.session_state.terraform_code = edited_code

    if st.button(
        "🔄 VALIDATE TERRAFORM",
        type="primary",
        use_container_width=True
    ):
        result = validate(
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

        audit(
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
            "Validate the Terraform to see security results."
        )
        return

    st.subheader("3. Security Validation Results")

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
            "The Terraform configuration is compliant. "
            "No correction is required."
        )

        return

    st.error(
        f'❌ VALIDATION FAILED — {result["failed"]} finding(s)'
    )

    dataframe = pd.DataFrame(
        result["results"]
    )

    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True
    )

    failed = [
        item
        for item in result["results"]
        if item["status"] == "FAILED"
    ]

    st.subheader("4. AI Remediation")

    st.warning(
        "Security issues were found. Generate corrected Terraform, review it, apply it, and revalidate it."
    )

    if st.button(
        "🤖 GENERATE AI CORRECTION",
        type="primary",
        use_container_width=True
    ):
        st.session_state.suggested_code = (
            generate_correction(
                st.session_state.terraform_code,
                failed
            )
        )

        audit(
            "AI Correction Generated",
            f"{len(failed)} finding(s)"
        )

        st.rerun()

    if st.session_state.suggested_code:
        st.markdown(
            "### 🤖 Suggested Corrected Terraform"
        )

        st.code(
            st.session_state.suggested_code,
            language="hcl"
        )

        st.warning(
            "Review the corrected code before applying it."
        )

        if st.button(
            "✅ APPLY CORRECTED CODE",
            use_container_width=True
        ):
            st.session_state.terraform_code = (
                st.session_state.suggested_code
            )

            st.session_state.validation_result = None

            audit(
                "Corrected Terraform Applied"
            )

            st.success(
                "Correction applied. Now click VALIDATE TERRAFORM."
            )

            st.rerun()


def policy_section():
    st.subheader("1. Company Security Policy")

    st.write(
        "Terraform is validated against the company security policy and Checkov."
    )

    st.dataframe(
        pd.DataFrame(
            st.session_state.policy
        ),
        use_container_width=True,
        hide_index=True
    )

    with st.expander(
        "✏️ Edit Company Policy"
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
                    st.session_state.policy = new_policy

                    audit(
                        "Company Policy Updated"
                    )

                    st.success(
                        "Policy saved."
                    )

                    st.rerun()

            except Exception as error:
                st.error(
                    f"Invalid policy: {error}"
                )


def cvs_section():
    st.subheader("5. CVS Source Control")

    cvs_available = shutil.which(
        "cvs"
    ) is not None

    if cvs_available:
        st.success(
            "CVS command is available."
        )
    else:
        st.warning(
            "CVS command is not available in this environment."
        )

    cvs_root = st.text_input(
        "CVSROOT",
        placeholder="/path/to/cvsroot"
    )

    cvs_module = st.text_input(
        "CVS Module",
        placeholder="terraform-project"
    )

    workspace = st.text_input(
        "CVS Workspace",
        value=os.path.join(
            tempfile.gettempdir(),
            "iac_cvs_workspace"
        )
    )

    os.makedirs(
        workspace,
        exist_ok=True
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        if st.button(
            "📥 CHECKOUT",
            use_container_width=True
        ):
            if not cvs_root or not cvs_module:
                st.error(
                    "Enter CVSROOT and module."
                )
            else:
                success, output = cvs_command(
                    [
                        "cvs",
                        "-d",
                        cvs_root,
                        "checkout",
                        cvs_module
                    ],
                    workspace
                )

                if success:
                    st.success(
                        "CVS checkout completed."
                    )
                else:
                    st.error(
                        "CVS checkout failed."
                    )

                st.code(output)

    with c2:
        if st.button(
            "🔄 UPDATE",
            use_container_width=True
        ):
            success, output = cvs_command(
                [
                    "cvs",
                    "update",
                    "-dP"
                ],
                workspace
            )

            st.code(output)

            if success:
                st.success(
                    "CVS update completed."
                )

    with c3:
        if st.button(
            "🔎 DIFF",
            use_container_width=True
        ):
            success, output = cvs_command(
                [
                    "cvs",
                    "diff"
                ],
                workspace
            )

            st.code(output)

    commit_message = st.text_input(
        "Commit Message",
        value="Validated Terraform configuration"
    )

    if st.button(
        "🔐 VALIDATE + CVS COMMIT",
        type="primary",
        use_container_width=True
    ):
        current_result = validate(
            st.session_state.terraform_code
        )

        st.session_state.validation_result = (
            current_result
        )

        if not current_result["overall_passed"]:
            st.error(
                "🚫 CVS COMMIT BLOCKED — Terraform failed security validation."
            )

            audit(
                "CVS Commit Blocked",
                f'{current_result["failed"]} failure(s)'
            )

            st.rerun()

        filename = st.session_state.source_name

        file_path = os.path.join(
            workspace,
            filename
        )

        try:
            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as file:
                file.write(
                    st.session_state.terraform_code
                )

            add_success, add_output = cvs_command(
                [
                    "cvs",
                    "add",
                    filename
                ],
                workspace
            )

            commit_success, commit_output = cvs_command(
                [
                    "cvs",
                    "commit",
                    "-m",
                    commit_message
                ],
                workspace
            )

            if commit_success:
                st.success(
                    "✅ VALIDATION PASSED — CVS COMMIT COMPLETED."
                )

                audit(
                    "CVS Commit Completed",
                    commit_message
                )
            else:
                st.error(
                    "Validation passed, but CVS commit failed."
                )

            st.code(
                add_output
                + "\n"
                + commit_output
            )

        except Exception as error:
            st.error(
                f"CVS error: {error}"
            )


def history_section():
    st.subheader("6. Validation History")

    if st.session_state.history:
        st.dataframe(
            pd.DataFrame(
                st.session_state.history
            ),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info(
            "No validation history yet."
        )


def audit_section():
    st.subheader("7. Audit Log")

    if st.session_state.audit_log:
        st.dataframe(
            pd.DataFrame(
                st.session_state.audit_log
            ),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info(
            "No audit events yet."
        )


st.title(
    "🛡️ AI-IAC Security Configuration Validator"
)

st.markdown(
    """
**Terraform → Company Policy → Checkov → Findings → AI Remediation → Revalidation → CVS**

The application does not declare corrected Terraform secure until the corrected code has been validated again.
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
