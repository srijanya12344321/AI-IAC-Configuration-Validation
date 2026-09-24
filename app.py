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
        "description": "SSH rules must use TCP port 22.",
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

if "selected_source" not in st.session_state:
    st.session_state.selected_source = "Safe Demo"

if "validation_result" not in st.session_state:
    st.session_state.validation_result = None

if "suggested_code" not in st.session_state:
    st.session_state.suggested_code = ""

if "history" not in st.session_state:
    st.session_state.history = []

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "cvs_root" not in st.session_state:
    st.session_state.cvs_root = ""

if "cvs_module" not in st.session_state:
    st.session_state.cvs_module = ""

if "cvs_workspace" not in st.session_state:
    st.session_state.cvs_workspace = os.path.join(
        tempfile.gettempdir(),
        "ai_iac_cvs_workspace"
    )


def add_audit(action, details=""):
    st.session_state.audit_log.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "details": details
        }
    )


def normalize_code(code):
    return code.replace("\r\n", "\n").replace("\r", "\n")


def policy_rule_result(rule, code):
    rule_type = rule.get("type", "")
    rule_id = rule.get("id", "")
    name = rule.get("name", "")
    severity = rule.get("severity", "MEDIUM")

    code_normalized = normalize_code(code)

    if rule_type == "public_ssh":
        ssh_blocks = re.findall(
            r'(?s)(?:ingress|rule)\s*\{.*?\}',
            code_normalized,
            re.IGNORECASE
        )

        public_ssh = False

        for block in ssh_blocks:
            has_ssh = bool(
                re.search(
                    r'from_port\s*=\s*22',
                    block
                )
                or
                re.search(
                    r'to_port\s*=\s*22',
                    block
                )
            )

            has_public = "0.0.0.0/0" in block

            if has_ssh and has_public:
                public_ssh = True
                break

        passed = not public_ssh

        return {
            "id": rule_id,
            "name": name,
            "severity": severity,
            "source": "Company Policy",
            "status": "PASSED" if passed else "FAILED",
            "reason": (
                "No public SSH access was detected."
                if passed
                else "SSH port 22 is exposed to 0.0.0.0/0."
            )
        }

    if rule_type == "ssh_port":
        ssh_blocks = re.findall(
            r'(?s)(?:ingress|rule)\s*\{.*?\}',
            code_normalized,
            re.IGNORECASE
        )

        invalid_ssh = False
        ssh_found = False

        for block in ssh_blocks:
            has_ssh = (
                bool(re.search(r'from_port\s*=\s*22', block))
                or
                bool(re.search(r'to_port\s*=\s*22', block))
            )

            if has_ssh:
                ssh_found = True

                from_match = re.search(
                    r'from_port\s*=\s*(\d+)',
                    block
                )

                to_match = re.search(
                    r'to_port\s*=\s*(\d+)',
                    block
                )

                if from_match and to_match:
                    if from_match.group(1) != "22" or to_match.group(1) != "22":
                        invalid_ssh = True

        passed = not invalid_ssh

        return {
            "id": rule_id,
            "name": name,
            "severity": severity,
            "source": "Company Policy",
            "status": "PASSED" if passed else "FAILED",
            "reason": (
                "SSH rules use port 22."
                if passed
                else "An SSH rule does not use port 22."
            )
        }

    if rule_type == "security_group_description":
        security_groups = re.findall(
            r'(?s)resource\s+"aws_security_group"\s+"[^"]+"\s*\{(.*?)\}',
            code_normalized,
            re.IGNORECASE
        )

        passed = True

        for block in security_groups:
            if not re.search(
                r'\bdescription\s*=',
                block
            ):
                passed = False
                break

        return {
            "id": rule_id,
            "name": name,
            "severity": severity,
            "source": "Company Policy",
            "status": "PASSED" if passed else "FAILED",
            "reason": (
                "Security groups contain descriptions."
                if passed
                else "A security group is missing a description."
            )
        }

    forbidden_text = rule.get("forbidden_text")

    if forbidden_text:
        passed = forbidden_text not in code_normalized

        return {
            "id": rule_id,
            "name": name,
            "severity": severity,
            "source": "Company Policy",
            "status": "PASSED" if passed else "FAILED",
            "reason": (
                "Forbidden configuration was not found."
                if passed
                else f"Forbidden configuration detected: {forbidden_text}"
            )
        }

    required_text = rule.get("required_text")

    if required_text:
        passed = required_text in code_normalized

        return {
            "id": rule_id,
            "name": name,
            "severity": severity,
            "source": "Company Policy",
            "status": "PASSED" if passed else "FAILED",
            "reason": (
                "Required configuration was found."
                if passed
                else f"Required configuration missing: {required_text}"
            )
        }

    regex_pattern = rule.get("regex")

    if regex_pattern:
        try:
            passed = bool(re.search(regex_pattern, code_normalized))
        except re.error:
            passed = False

        return {
            "id": rule_id,
            "name": name,
            "severity": severity,
            "source": "Company Policy",
            "status": "PASSED" if passed else "FAILED",
            "reason": (
                "Required pattern was found."
                if passed
                else "Required pattern was not found."
            )
        }

    return {
        "id": rule_id,
        "name": name,
        "severity": severity,
        "source": "Company Policy",
        "status": "SKIPPED",
        "reason": "Unsupported policy rule type."
    }


def run_company_policy(code):
    results = []

    for rule in st.session_state.policy:
        results.append(
            policy_rule_result(
                rule,
                code
            )
        )

    return results


def run_checkov(code):
    if shutil.which("checkov") is None:
        return [
            {
                "id": "CHECKOV-UNAVAILABLE",
                "name": "Checkov",
                "severity": "INFO",
                "source": "Checkov",
                "status": "SKIPPED",
                "reason": "Checkov executable is not installed."
            }
        ]

    temp_dir = tempfile.mkdtemp(prefix="iac_check_")
    tf_path = os.path.join(
        temp_dir,
        "main.tf"
    )

    try:
        with open(
            tf_path,
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

        raw_output = process.stdout.strip()

        if not raw_output:
            if process.returncode == 0:
                return [
                    {
                        "id": "CKV-AWS-24",
                        "name": "No public SSH access",
                        "severity": "HIGH",
                        "source": "Checkov",
                        "status": "PASSED",
                        "reason": "Checkov did not detect public SSH exposure."
                    }
                ]

            return [
                {
                    "id": "CHECKOV-ERROR",
                    "name": "Checkov Execution",
                    "severity": "INFO",
                    "source": "Checkov",
                    "status": "SKIPPED",
                    "reason": process.stderr.strip() or "No Checkov output."
                }
            ]

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            return [
                {
                    "id": "CHECKOV-OUTPUT",
                    "name": "Checkov Output",
                    "severity": "INFO",
                    "source": "Checkov",
                    "status": "SKIPPED",
                    "reason": "Checkov returned output that could not be parsed."
                }
            ]

        results = []

        summary = parsed.get("summary", {})

        passed_checks = summary.get(
            "passed",
            0
        )

        failed_checks = summary.get(
            "failed",
            0
        )

        results_data = parsed.get(
            "results",
            {}
        )

        failed_checks_data = results_data.get(
            "failed_checks",
            []
        )

        passed_checks_data = results_data.get(
            "passed_checks",
            []
        )

        for item in failed_checks_data:
            results.append(
                {
                    "id": item.get(
                        "check_id",
                        "CHECKOV"
                    ),
                    "name": item.get(
                        "check_name",
                        "Checkov security check"
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

        if failed_checks == 0:
            results.append(
                {
                    "id": "CKV-AWS-24",
                    "name": "No public SSH access",
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "PASSED",
                    "reason": "Checkov did not detect public SSH exposure."
                }
            )
        elif not failed_checks_data and passed_checks > 0:
            results.append(
                {
                    "id": "CKV-AWS-24",
                    "name": "No public SSH access",
                    "severity": "HIGH",
                    "source": "Checkov",
                    "status": "PASSED",
                    "reason": "Checkov passed the configured security check."
                }
            )

        return results

    except subprocess.TimeoutExpired:
        return [
            {
                "id": "CHECKOV-TIMEOUT",
                "name": "Checkov Execution",
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


def validate_code(code):
    policy_results = run_company_policy(code)
    checkov_results = run_checkov(code)

    all_results = policy_results + checkov_results

    passed = sum(
        1 for item in all_results
        if item["status"] == "PASSED"
    )

    failed = sum(
        1 for item in all_results
        if item["status"] == "FAILED"
    )

    skipped = sum(
        1 for item in all_results
        if item["status"] == "SKIPPED"
    )

    total = len(all_results)

    overall_passed = failed == 0

    return {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "total": total,
        "overall_passed": overall_passed,
        "results": all_results,
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }


def generate_corrected_code(code, results):
    corrected = code

    failed_ids = {
        item["id"]
        for item in results
        if item["status"] == "FAILED"
    }

    public_ssh_failed = (
        "POLICY-SSH-001" in failed_ids
        or
        "CKV_AWS_24" in failed_ids
        or
        "CKV_AWS_24".lower() in {
            str(item).lower()
            for item in failed_ids
        }
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
            r'(from_port\s*=\s*)\d+',
            r'\g<1>22',
            corrected
        )

        corrected = re.sub(
            r'(to_port\s*=\s*)\d+',
            r'\g<1>22',
            corrected
        )

    if description_failed:
        pattern = (
            r'(resource\s+"aws_security_group"\s+"[^"]+"\s*\{\s*'
            r'name\s*=\s*"[^"]+"\s*)'
        )

        replacement = (
            r'\1\n  description = '
            r'"Security group managed by security validation policy"\n'
        )

        corrected = re.sub(
            pattern,
            replacement,
            corrected,
            count=1
        )

    return corrected


def source_selector():
    st.subheader("2. Terraform Source")

    st.write(
        "Choose a built-in demonstration or test your own Terraform."
    )

    source = st.radio(
        "Select Terraform input",
        [
            "Safe Demo",
            "Unsafe Demo",
            "Upload Your Own Terraform"
        ],
        index=[
            "Safe Demo",
            "Unsafe Demo",
            "Upload Your Own Terraform"
        ].index(
            st.session_state.selected_source
            if st.session_state.selected_source in [
                "Safe Demo",
                "Unsafe Demo",
                "Upload Your Own Terraform"
            ]
            else "Safe Demo"
        ),
        horizontal=True
    )

    st.session_state.selected_source = source

    if source == "Safe Demo":
        st.session_state.terraform_code = SAFE_DEMO
        st.session_state.source_name = "safe_demo.tf"

    elif source == "Unsafe Demo":
        st.session_state.terraform_code = UNSAFE_DEMO
        st.session_state.source_name = "unsafe_demo.tf"

    else:
        uploaded_file = st.file_uploader(
            "Upload Terraform .tf file",
            type=["tf"]
        )

        if uploaded_file is not None:
            st.session_state.terraform_code = (
                uploaded_file.read()
                .decode("utf-8")
            )

            st.session_state.source_name = uploaded_file.name

            add_audit(
                "Terraform Uploaded",
                uploaded_file.name
            )

    st.text_input(
        "Terraform filename",
        value=st.session_state.source_name,
        key="terraform_filename"
    )

    st.session_state.source_name = st.session_state.terraform_filename

    st.text_area(
        "Terraform Code",
        value=st.session_state.terraform_code,
        height=430,
        key="terraform_editor"
    )

    st.session_state.terraform_code = st.session_state.terraform_editor

    col1, col2 = st.columns(2)

    with col1:
        if st.button(
            "🔄 VALIDATE TERRAFORM",
            use_container_width=True
        ):
            result = validate_code(
                st.session_state.terraform_code
            )

            st.session_state.validation_result = result
            st.session_state.suggested_code = ""

            st.session_state.history.insert(
                0,
                {
                    "time": result["timestamp"],
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

    with col2:
        if st.button(
            "🧹 RESET TO SELECTED DEMO",
            use_container_width=True
        ):
            if st.session_state.selected_source == "Safe Demo":
                st.session_state.terraform_code = SAFE_DEMO
                st.session_state.source_name = "safe_demo.tf"

            elif st.session_state.selected_source == "Unsafe Demo":
                st.session_state.terraform_code = UNSAFE_DEMO
                st.session_state.source_name = "unsafe_demo.tf"

            st.session_state.validation_result = None
            st.session_state.suggested_code = ""

            st.rerun()


def show_results():
    result = st.session_state.validation_result

    if result is None:
        st.info(
            "Run validation to see the security results."
        )
        return

    st.subheader("3. Validation Results")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Passed",
        result["passed"]
    )

    col2.metric(
        "Failed",
        result["failed"]
    )

    col3.metric(
        "Skipped",
        result["skipped"]
    )

    col4.metric(
        "Total",
        result["total"]
    )

    if result["overall_passed"]:
        st.success(
            "✅ ALL CHECKS PASSED — Terraform is compliant."
        )
    else:
        st.error(
            f'❌ VALIDATION FAILED — {result["failed"]} issue(s) require attention.'
        )

    dataframe = pd.DataFrame(
        result["results"]
    )

    if not dataframe.empty:
        st.dataframe(
            dataframe[
                [
                    "id",
                    "name",
                    "severity",
                    "source",
                    "status",
                    "reason"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

    failed_results = [
        item
        for item in result["results"]
        if item["status"] == "FAILED"
    ]

    if result["overall_passed"]:
        st.success(
            "No remediation is required. The secure Terraform passed the validation stage."
        )
        return

    st.subheader("4. Remediation")

    st.warning(
        "The Terraform has failed security validation. "
        "Generate a corrected version, review it, apply it, and then revalidate."
    )

    if st.button(
        "🤖 GENERATE CORRECTED CODE",
        use_container_width=True
    ):
        corrected = generate_corrected_code(
            st.session_state.terraform_code,
            failed_results
        )

        st.session_state.suggested_code = corrected

        add_audit(
            "Correction Generated",
            f'{len(failed_results)} finding(s) processed'
        )

        st.rerun()

    if st.session_state.suggested_code:
        st.markdown("### Suggested Corrected Terraform")

        st.code(
            st.session_state.suggested_code,
            language="hcl"
        )

        st.info(
            "Review the suggested Terraform before applying it."
        )

        if st.button(
            "✅ APPLY CORRECTED CODE",
            use_container_width=True
        ):
            st.session_state.terraform_code = (
                st.session_state.suggested_code
            )

            st.session_state.validation_result = None

            add_audit(
                "Corrected Code Applied",
                st.session_state.source_name
            )

            st.success(
                "Corrected code applied. Revalidate it to confirm the actual security result."
            )

            st.rerun()


def cvs_command(command, cwd=None):
    if shutil.which("cvs") is None:
        return False, "CVS executable is not installed."

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

    except Exception as error:
        return False, str(error)


def cvs_section():
    st.subheader("5. CVS Integration")

    if shutil.which("cvs") is None:
        st.warning(
            "CVS is not currently available in this environment. "
            "Install CVS using packages.txt for deployment."
        )

    st.write(
        "CVS is used for source control operations after security validation."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.session_state.cvs_root = st.text_input(
            "CVSROOT",
            value=st.session_state.cvs_root,
            placeholder="/path/to/cvsroot"
        )

    with col2:
        st.session_state.cvs_module = st.text_input(
            "CVS Module",
            value=st.session_state.cvs_module,
            placeholder="terraform-project"
        )

    st.session_state.cvs_workspace = st.text_input(
        "CVS Workspace",
        value=st.session_state.cvs_workspace
    )

    st.markdown("### CVS Operations")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            "📥 CVS CHECKOUT",
            use_container_width=True
        ):
            if not st.session_state.cvs_root:
                st.error("Enter CVSROOT first.")
            elif not st.session_state.cvs_module:
                st.error("Enter CVS module first.")
            else:
                os.makedirs(
                    st.session_state.cvs_workspace,
                    exist_ok=True
                )

                command = [
                    "cvs",
                    "-d",
                    st.session_state.cvs_root,
                    "checkout",
                    st.session_state.cvs_module
                ]

                success, output = cvs_command(
                    command,
                    st.session_state.cvs_workspace
                )

                if success:
                    st.success("CVS checkout completed.")
                else:
                    st.error("CVS checkout failed.")

                st.code(output)

    with col2:
        if st.button(
            "🔄 CVS UPDATE",
            use_container_width=True
        ):
            success, output = cvs_command(
                ["cvs", "update", "-dP"],
                st.session_state.cvs_workspace
            )

            if success:
                st.success("CVS update completed.")
            else:
                st.error("CVS update failed.")

            st.code(output)

    with col3:
        if st.button(
            "🔎 CVS DIFF",
            use_container_width=True
        ):
            success, output = cvs_command(
                ["cvs", "diff"],
                st.session_state.cvs_workspace
            )

            if success:
                st.success("CVS diff completed.")
            else:
                st.error("CVS diff returned differences or failed.")

            st.code(output)

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button(
            "➕ CVS ADD",
            use_container_width=True
        ):
            filename = st.session_state.source_name

            file_path = os.path.join(
                st.session_state.cvs_workspace,
                filename
            )

            try:
                os.makedirs(
                    os.path.dirname(file_path),
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

                success, output = cvs_command(
                    ["cvs", "add", filename],
                    st.session_state.cvs_workspace
                )

                if success:
                    st.success("File added to CVS.")
                else:
                    st.error("CVS add failed.")

                st.code(output)

            except Exception as error:
                st.error(str(error))

    with col2:
        commit_message = st.text_input(
            "Commit message",
            value="Validated Terraform security configuration"
        )

    with col3:
        if st.button(
            "📤 CVS COMMIT",
            use_container_width=True
        ):
            success, output = cvs_command(
                [
                    "cvs",
                    "commit",
                    "-m",
                    commit_message
                ],
                st.session_state.cvs_workspace
            )

            if success:
                st.success("CVS commit completed.")
                add_audit(
                    "CVS Commit",
                    commit_message
                )
            else:
                st.error("CVS commit failed.")

            st.code(output)

    if st.button(
        "🔐 VALIDATE + CVS COMMIT",
        use_container_width=True
    ):
        result = validate_code(
            st.session_state.terraform_code
        )

        st.session_state.validation_result = result

        if not result["overall_passed"]:
            st.error(
                "CVS COMMIT BLOCKED — Terraform failed security validation."
            )

            add_audit(
                "CVS Commit Blocked",
                f'{result["failed"]} security finding(s)'
            )

            return

        filename = st.session_state.source_name

        try:
            os.makedirs(
                st.session_state.cvs_workspace,
                exist_ok=True
            )

            file_path = os.path.join(
                st.session_state.cvs_workspace,
                filename
            )

            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as file:
                file.write(
                    st.session_state.terraform_code
                )

            add_success, add_output = cvs_command(
                ["cvs", "add", filename],
                st.session_state.cvs_workspace
            )

            if not add_success:
                st.warning(
                    "CVS add returned a non-success result. "
                    "The file may already be under CVS."
                )

            commit_success, commit_output = cvs_command(
                [
                    "cvs",
                    "commit",
                    "-m",
                    commit_message
                ],
                st.session_state.cvs_workspace
            )

            if commit_success:
                st.success(
                    "✅ VALIDATION PASSED — CVS COMMIT COMPLETED."
                )

                add_audit(
                    "Validated CVS Commit",
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
            st.error(str(error))


def policy_section():
    st.subheader("1. Company Security Policy")

    st.write(
        "The Terraform configuration is checked against company-defined security rules before it can be accepted."
    )

    dataframe = pd.DataFrame(
        st.session_state.policy
    )

    if not dataframe.empty:
        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True
        )

    with st.expander(
        "✏️ Edit Complete Policy"
    ):
        policy_text = st.text_area(
            "Policy JSON",
            value=json.dumps(
                st.session_state.policy,
                indent=2
            ),
            height=350
        )

        if st.button(
            "💾 SAVE POLICY"
        ):
            try:
                new_policy = json.loads(
                    policy_text
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

                    add_audit(
                        "Security Policy Updated",
                        f"{len(new_policy)} rule(s)"
                    )

                    st.success(
                        "Security policy updated."
                    )

                    st.rerun()

            except json.JSONDecodeError as error:
                st.error(
                    f"Invalid JSON: {error}"
                )

    with st.expander(
        "➕ Add New Policy Rule"
    ):
        new_id = st.text_input(
            "Rule ID",
            placeholder="POLICY-CUSTOM-001"
        )

        new_name = st.text_input(
            "Rule Name",
            placeholder="No unrestricted database access"
        )

        new_description = st.text_input(
            "Description"
        )

        new_severity = st.selectbox(
            "Severity",
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]
        )

        new_type = st.selectbox(
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

        custom_value = st.text_input(
            "Rule Value",
            placeholder="Used by forbidden_text, required_text, or regex"
        )

        if st.button(
            "➕ ADD RULE"
        ):
            if not new_id or not new_name:
                st.error(
                    "Rule ID and Rule Name are required."
                )
            else:
                new_rule = {
                    "id": new_id,
                    "name": new_name,
                    "description": new_description,
                    "severity": new_severity,
                    "type": new_type
                }

                if new_type == "forbidden_text":
                    new_rule["forbidden_text"] = custom_value

                if new_type == "required_text":
                    new_rule["required_text"] = custom_value

                if new_type == "regex":
                    new_rule["regex"] = custom_value

                st.session_state.policy.append(
                    new_rule
                )

                add_audit(
                    "Policy Rule Added",
                    new_id
                )

                st.success(
                    "New policy rule added."
                )

                st.rerun()


def history_section():
    st.subheader("6. Validation History")

    if not st.session_state.history:
        st.info(
            "No validation history yet."
        )
    else:
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
    else:
        st.dataframe(
            pd.DataFrame(
                st.session_state.audit_log
            ),
            use_container_width=True,
            hide_index=True
        )


st.title("🛡️ AI-IAC Security Configuration Validator")

st.markdown(
    """
### Terraform Security Validation and Remediation

This application validates Infrastructure-as-Code against:

- Company Security Policy
- Checkov security scanning
- Security findings and severity
- Terraform remediation workflow
- Revalidation after correction
- CVS source-control integration
- Validation history
- Audit logging
"""
)

st.divider()

policy_section()

st.divider()

source_selector()

st.divider()

show_results()

st.divider()

cvs_section()

st.divider()

history_section()

st.divider()

audit_section()
