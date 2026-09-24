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
    page_title="AI-IAC Security Validation",
    page_icon="🛡️",
    layout="wide"
)


SAFE_DEMO = """
terraform {
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
"""


UNSAFE_DEMO = """
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "unsafe_demo" {
  name        = "unsafe-demo"
  description = "Security group with public SSH access"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound access"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


DEFAULT_POLICY = {
    "name": "Company Security Policy",
    "version": "1.0",
    "rules": [
        {
            "id": "POLICY-SSH-001",
            "name": "No Public SSH",
            "description": "SSH must not be accessible from 0.0.0.0/0",
            "severity": "HIGH",
            "type": "forbidden_text",
            "pattern": 'cidr_blocks = ["0.0.0.0/0"]'
        },
        {
            "id": "POLICY-SSH-002",
            "name": "SSH Port Must Be 22",
            "description": "SSH ingress must use port 22",
            "severity": "MEDIUM",
            "type": "required_text",
            "pattern": "to_port   = 22"
        },
        {
            "id": "POLICY-DESC-001",
            "name": "Security Group Needs Description",
            "description": "Security groups must have a description",
            "severity": "MEDIUM",
            "type": "required_text",
            "pattern": "description ="
        }
    ]
}


def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def initialize_state():
    defaults = {
        "terraform_code": SAFE_DEMO,
        "filename": "safe_demo.tf",
        "policy": json.loads(json.dumps(DEFAULT_POLICY)),
        "policy_json": json.dumps(DEFAULT_POLICY, indent=2),
        "last_result": None,
        "validation_history": [],
        "audit_log": [],
        "selected_finding": None,
        "suggested_code": "",
        "ai_explanation": "",
        "ai_status": "",
        "cvs_output": ""
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_state()


def add_audit(event, status="INFO", details=""):
    st.session_state.audit_log.insert(
        0,
        {
            "Time": current_time(),
            "Event": event,
            "Status": status,
            "Details": details
        }
    )

    st.session_state.audit_log = st.session_state.audit_log[:100]


def add_validation_history(result):
    st.session_state.validation_history.insert(
        0,
        {
            "Time": current_time(),
            "File": result["filename"],
            "Passed": result["passed"],
            "Failed": result["failed"],
            "Skipped": result["skipped"],
            "Total": result["total"],
            "Result": result["overall"]
        }
    )

    st.session_state.validation_history = (
        st.session_state.validation_history[:50]
    )


def get_executable(name):
    return shutil.which(name)


def run_command(command, cwd=None, env=None, timeout=180):
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = (
            (result.stdout or "")
            + "\n"
            + (result.stderr or "")
        ).strip()

        return result.returncode, output

    except FileNotFoundError:
        return 127, f"Command not found: {command[0]}"

    except subprocess.TimeoutExpired:
        return 124, "Command timed out."

    except Exception as exc:
        return 1, str(exc)


def extract_json(text):
    decoder = json.JSONDecoder()

    for match in re.finditer(r"[\{\[]", text):
        try:
            value, _ = decoder.raw_decode(
                text[match.start():]
            )

            if isinstance(value, dict):
                return value

        except Exception:
            continue

    return None


def checkov_item(item, result_type):
    return {
        "id": item.get("check_id", "UNKNOWN"),
        "name": item.get(
            "check_name",
            item.get("check_id", "Unknown Check")
        ),
        "file": item.get("file_path", ""),
        "resource": item.get("resource", ""),
        "guideline": item.get("guideline", ""),
        "type": result_type,
        "severity": item.get("severity", "")
    }


def parse_checkov(data):
    if not isinstance(data, dict):
        return [], [], []

    results = data.get("results", {})

    passed = [
        checkov_item(item, "Checkov")
        for item in (
            results.get("passed_checks", []) or []
        )
    ]

    failed = [
        checkov_item(item, "Checkov")
        for item in (
            results.get("failed_checks", []) or []
        )
    ]

    skipped = [
        checkov_item(item, "Checkov")
        for item in (
            results.get("skipped_checks", []) or []
        )
    ]

    return passed, failed, skipped


def run_checkov(code, filename):
    checkov_path = get_executable("checkov")

    if checkov_path:
        command = [
            checkov_path,
            "-f",
            "",
            "--framework",
            "terraform",
            "-o",
            "json"
        ]
    else:
        command = [
            "python",
            "-m",
            "checkov",
            "-f",
            "",
            "--framework",
            "terraform",
            "-o",
            "json"
        ]

    with tempfile.TemporaryDirectory() as temp_dir:

        safe_filename = os.path.basename(
            filename or "main.tf"
        )

        if not safe_filename.endswith(".tf"):
            safe_filename += ".tf"

        file_path = os.path.join(
            temp_dir,
            safe_filename
        )

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:
            file.write(code)

        command[2] = file_path

        return_code, output = run_command(
            command,
            cwd=temp_dir,
            timeout=180
        )

        data = extract_json(output)

        if data is None:
            return {
                "available": return_code != 127,
                "return_code": return_code,
                "passed": [],
                "failed": [],
                "skipped": [],
                "error": "Checkov did not return readable JSON.",
                "raw_output": output
            }

        passed, failed, skipped = parse_checkov(data)

        return {
            "available": True,
            "return_code": return_code,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "error": "",
            "raw_output": output
        }


def run_company_policy(code, policy):
    passed = []
    failed = []

    for rule in policy.get("rules", []):

        rule_id = rule.get(
            "id",
            "POLICY-UNKNOWN"
        )

        name = rule.get(
            "name",
            rule_id
        )

        description = rule.get(
            "description",
            ""
        )

        severity = rule.get(
            "severity",
            "MEDIUM"
        )

        rule_type = rule.get(
            "type",
            "forbidden_text"
        )

        pattern = rule.get(
            "pattern",
            ""
        )

        base = {
            "id": rule_id,
            "name": name,
            "description": description,
            "severity": severity,
            "type": "Company Policy"
        }

        if not pattern:
            failed.append({
                **base,
                "reason": "Policy pattern is empty."
            })
            continue

        if rule_type == "forbidden_text":

            if pattern in code:
                failed.append({
                    **base,
                    "reason": f"Forbidden text found: {pattern}"
                })
            else:
                passed.append(base)

        elif rule_type == "required_text":

            if pattern in code:
                passed.append(base)
            else:
                failed.append({
                    **base,
                    "reason": f"Required text not found: {pattern}"
                })

        elif rule_type == "regex":

            try:
                matched = re.search(
                    pattern,
                    code,
                    re.MULTILINE
                ) is not None

                regex_error = ""

            except re.error as exc:
                matched = False
                regex_error = str(exc)

            if matched:
                passed.append(base)

            else:
                reason = (
                    f"Invalid regex: {regex_error}"
                    if regex_error
                    else f"Regex condition failed: {pattern}"
                )

                failed.append({
                    **base,
                    "reason": reason
                })

        else:
            failed.append({
                **base,
                "reason": f"Unsupported rule type: {rule_type}"
            })

    return passed, failed


def validate_code():
    code = st.session_state.terraform_code

    filename = (
        st.session_state.filename
        or "main.tf"
    )

    if not filename.endswith(".tf"):
        filename += ".tf"

    company_passed, company_failed = run_company_policy(
        code,
        st.session_state.policy
    )

    checkov = run_checkov(
        code,
        filename
    )

    passed = company_passed + checkov["passed"]
    failed = company_failed + checkov["failed"]
    skipped = checkov["skipped"]

    total = (
        len(passed)
        + len(failed)
        + len(skipped)
    )

    overall = (
        "PASS"
        if len(failed) == 0
        else "FAIL"
    )

    result = {
        "time": current_time(),
        "filename": filename,
        "passed": len(passed),
        "failed": len(failed),
        "skipped": len(skipped),
        "total": total,
        "overall": overall,
        "passed_checks": passed,
        "failed_checks": failed,
        "skipped_checks": skipped,
        "checkov": checkov
    }

    st.session_state.last_result = result
    st.session_state.suggested_code = ""
    st.session_state.ai_explanation = ""
    st.session_state.ai_status = ""

    add_validation_history(result)

    add_audit(
        "Validation completed",
        overall,
        (
            f"Passed={len(passed)}, "
            f"Failed={len(failed)}, "
            f"Skipped={len(skipped)}"
        )
    )

    return result


def build_failure_context(result):
    failures = []

    for item in result.get("failed_checks", []):

        if item.get("type") == "Company Policy":

            failures.append(
                {
                    "source": "Company Policy",
                    "id": item.get("id", ""),
                    "name": item.get("name", ""),
                    "severity": item.get("severity", ""),
                    "description": item.get(
                        "description",
                        ""
                    ),
                    "reason": item.get(
                        "reason",
                        ""
                    )
                }
            )

        else:

            failures.append(
                {
                    "source": "Checkov",
                    "id": item.get("id", ""),
                    "name": item.get("name", ""),
                    "severity": item.get("severity", ""),
                    "resource": item.get(
                        "resource",
                        ""
                    ),
                    "guideline": item.get(
                        "guideline",
                        ""
                    )
                }
            )

    return failures


def fallback_ai_correction(code, failures):
    corrected = code

    for failure in failures:

        text = (
            str(failure.get("name", ""))
            + " "
            + str(failure.get("reason", ""))
            + " "
            + str(failure.get("guideline", ""))
        ).lower()

        if (
            "public ssh" in text
            or "0.0.0.0/0" in text
            or "ssh" in text
            and "public" in text
        ):
            corrected = corrected.replace(
                'cidr_blocks = ["0.0.0.0/0"]',
                'cidr_blocks = ["10.0.0.0/24"]'
            )

    return corrected


def call_ai_for_correction(code, failures):
    api_key = os.environ.get(
        "OPENAI_API_KEY",
        ""
    )

    if not api_key:
        return (
            fallback_ai_correction(
                code,
                failures
            ),
            "Fallback correction used because OPENAI_API_KEY is not configured."
        )

    try:
        from openai import OpenAI

        client = OpenAI(
            api_key=api_key
        )

        failure_text = json.dumps(
            failures,
            indent=2
        )

        prompt = f"""
You are an Infrastructure-as-Code security remediation assistant.

Analyze the Terraform code and every failed security validation below.

Your task:
1. Fix the security problems.
2. Preserve the user's intended infrastructure where possible.
3. Do not remove resources just to make the scan pass.
4. Do not invent credentials, secrets, tokens, IDs, or infrastructure.
5. Preserve valid Terraform syntax.
6. Return the complete corrected Terraform code.
7. Do not return Markdown fences.
8. Do not return explanations before or after the Terraform code.

FAILED CHECKS:
{failure_text}

TERRAFORM:
{code}
"""

        response = client.chat.completions.create(
            model=os.environ.get(
                "OPENAI_MODEL",
                "gpt-4o-mini"
            ),
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Terraform security remediation "
                        "assistant. Return only corrected Terraform."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        corrected = response.choices[0].message.content.strip()

        corrected = re.sub(
            r"^```(?:hcl|terraform)?\s*",
            "",
            corrected
        )

        corrected = re.sub(
            r"\s*```$",
            "",
            corrected
        )

        if not corrected.strip():
            raise ValueError(
                "AI returned empty Terraform."
            )

        return (
            corrected,
            "AI generated a correction for the failed checks."
        )

    except Exception as exc:

        return (
            fallback_ai_correction(
                code,
                failures
            ),
            f"AI unavailable, fallback correction used: {exc}"
        )


def generate_ai_correction(result):
    if not result:
        return None

    if result["failed"] == 0:
        return None

    failures = build_failure_context(
        result
    )

    corrected_code, status = call_ai_for_correction(
        st.session_state.terraform_code,
        failures
    )

    st.session_state.suggested_code = corrected_code
    st.session_state.ai_status = status

    add_audit(
        "AI correction generated",
        "INFO",
        f"{len(failures)} failed checks analyzed"
    )

    return corrected_code


def load_demo(demo):
    if demo == "safe":
        st.session_state.terraform_code = SAFE_DEMO
        st.session_state.filename = "safe_demo.tf"
    else:
        st.session_state.terraform_code = UNSAFE_DEMO
        st.session_state.filename = "unsafe_demo.tf"

    st.session_state.last_result = None
    st.session_state.suggested_code = ""
    st.session_state.ai_explanation = ""
    st.session_state.ai_status = ""

    add_audit(
        "Demo loaded",
        "INFO",
        demo
    )


def explain_finding(finding):
    if not finding:
        return ""

    if finding.get("type") == "Company Policy":
        return (
            f"Policy: {finding.get('name', '')}\n\n"
            f"Description: {finding.get('description', '')}\n\n"
            f"Reason: {finding.get('reason', '')}"
        )

    return (
        f"Checkov check: {finding.get('name', '')}\n\n"
        f"Check ID: {finding.get('id', '')}\n\n"
        f"Resource: {finding.get('resource', '')}\n\n"
        f"Guideline: {finding.get('guideline', '')}"
    )


def show_validation_results(result):
    if not result:
        st.info(
            "No validation result yet. Click REVALIDATE CODE."
        )
        return

    st.subheader(
        "Validation Summary"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "PASSED",
        result["passed"]
    )

    col2.metric(
        "FAILED",
        result["failed"]
    )

    col3.metric(
        "SKIPPED",
        result["skipped"]
    )

    col4.metric(
        "TOTAL",
        result["total"]
    )

    if result["overall"] == "PASS":

        st.success(
            "✓ ALL CHECKS PASSED"
        )

    else:

        st.error(
            f"✗ VALIDATION FAILED — "
            f"{result['failed']} CHECK(S) FAILED"
        )

    st.write(
        f"File: `{result['filename']}`"
    )

    st.write(
        f"Validation time: `{result['time']}`"
    )

    passed_tab, failed_tab, skipped_tab = st.tabs(
        [
            f"✓ Passed ({result['passed']})",
            f"✗ Failed ({result['failed']})",
            f"⊘ Skipped ({result['skipped']})"
        ]
    )

    with passed_tab:

        if result["passed_checks"]:

            rows = []

            for item in result["passed_checks"]:
                rows.append(
                    {
                        "ID": item.get("id", ""),
                        "Check": item.get("name", ""),
                        "Type": item.get("type", ""),
                        "Severity": item.get("severity", "")
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

        else:
            st.info(
                "No checks passed."
            )

    with failed_tab:

        if result["failed_checks"]:

            failed_rows = []

            for item in result["failed_checks"]:
                failed_rows.append(
                    {
                        "ID": item.get("id", ""),
                        "Check": item.get("name", ""),
                        "Severity": item.get("severity", ""),
                        "Type": item.get("type", ""),
                        "Reason": item.get(
                            "reason",
                            item.get(
                                "guideline",
                                ""
                            )
                        )
                    }
                )

            st.dataframe(
                pd.DataFrame(failed_rows),
                use_container_width=True,
                hide_index=True
            )

            st.subheader(
                "Failed Check Details"
            )

            options = []

            for item in result["failed_checks"]:
                options.append(
                    f"{item.get('id', '')} - "
                    f"{item.get('name', '')}"
                )

            selected = st.selectbox(
                "Select failed check",
                range(len(options)),
                format_func=lambda x: options[x],
                key="failed_check_selector"
            )

            finding = result[
                "failed_checks"
            ][selected]

            st.warning(
                explain_finding(
                    finding
                )
            )

            st.divider()

            st.subheader(
                "🤖 AI Security Remediation"
            )

            st.write(
                f"AI can analyze all {result['failed']} "
                f"failed checks and generate corrected Terraform."
            )

            if st.button(
                "🤖 GENERATE AI CORRECTED CODE",
                type="primary",
                use_container_width=True
            ):

                with st.spinner(
                    "AI is analyzing all failed checks..."
                ):

                    generate_ai_correction(
                        result
                    )

                st.rerun()

            if st.session_state.ai_status:
                st.info(
                    st.session_state.ai_status
                )

            if st.session_state.suggested_code:

                st.subheader(
                    "🤖 AI Suggested Corrected Terraform"
                )

                st.code(
                    st.session_state.suggested_code,
                    language="hcl"
                )

                col1, col2 = st.columns(2)

                with col1:

                    if st.button(
                        "✅ APPLY AI CORRECTION",
                        type="primary",
                        use_container_width=True
                    ):

                        st.session_state.terraform_code = (
                            st.session_state.suggested_code
                        )

                        st.session_state.last_result = None
                        st.session_state.ai_status = (
                            "AI correction applied. "
                            "Revalidation is required."
                        )

                        add_audit(
                            "AI correction applied",
                            "INFO"
                        )

                        st.rerun()

                with col2:

                    if st.button(
                        "🔄 REVALIDATE CORRECTED CODE",
                        use_container_width=True
                    ):

                        with st.spinner(
                            "Revalidating corrected Terraform..."
                        ):

                            new_result = validate_code()

                        st.rerun()

        else:

            st.success(
                "✓ No failed checks."
            )

    with skipped_tab:

        if result["skipped_checks"]:

            rows = []

            for item in result["skipped_checks"]:
                rows.append(
                    {
                        "ID": item.get("id", ""),
                        "Check": item.get("name", ""),
                        "Type": item.get("type", "")
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "No skipped checks."
            )

    if result["checkov"].get("error"):

        st.warning(
            result["checkov"]["error"]
        )


def policy_section():
    st.header(
        "1. Company Security Policy"
    )

    policy = st.session_state.policy

    col1, col2 = st.columns(
        [3, 1]
    )

    with col1:

        policy_name = st.text_input(
            "Policy Name",
            value=policy.get(
                "name",
                "Company Security Policy"
            )
        )

    with col2:

        policy_version = st.text_input(
            "Version",
            value=policy.get(
                "version",
                "1.0"
            )
        )

    st.write(
        "Current Policy Rules"
    )

    rules = policy.get(
        "rules",
        []
    )

    if rules:

        rows = []

        for rule in rules:
            rows.append(
                {
                    "ID": rule.get("id", ""),
                    "Name": rule.get("name", ""),
                    "Severity": rule.get("severity", ""),
                    "Type": rule.get("type", ""),
                    "Pattern": rule.get("pattern", "")
                }
            )

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True
        )

    with st.expander(
        "Edit Complete Policy"
    ):

        policy_json = st.text_area(
            "Policy JSON",
            value=st.session_state.policy_json,
            height=300
        )

        if st.button(
            "Save Policy"
        ):

            try:

                new_policy = json.loads(
                    policy_json
                )

                if not isinstance(
                    new_policy,
                    dict
                ):
                    raise ValueError(
                        "Policy must be a JSON object."
                    )

                if "rules" not in new_policy:
                    raise ValueError(
                        "Policy must contain rules."
                    )

                new_policy["name"] = policy_name
                new_policy["version"] = policy_version

                st.session_state.policy = new_policy

                st.session_state.policy_json = json.dumps(
                    new_policy,
                    indent=2
                )

                st.session_state.last_result = None

                add_audit(
                    "Security policy updated",
                    "INFO"
                )

                st.success(
                    "Policy updated successfully. "
                    "Click REVALIDATE CODE."
                )

            except Exception as exc:

                st.error(
                    f"Invalid policy JSON: {exc}"
                )

    with st.expander(
        "Add New Policy Rule"
    ):

        with st.form(
            "new_policy_rule"
        ):

            rule_id = st.text_input(
                "Rule ID",
                value="POLICY-NEW-001"
            )

            rule_name = st.text_input(
                "Rule Name"
            )

            description = st.text_area(
                "Description"
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
                    "forbidden_text",
                    "required_text",
                    "regex"
                ]
            )

            pattern = st.text_input(
                "Pattern"
            )

            submitted = st.form_submit_button(
                "Add Policy Rule"
            )

            if submitted:

                if not rule_name:

                    st.error(
                        "Rule name is required."
                    )

                elif not pattern:

                    st.error(
                        "Pattern is required."
                    )

                else:

                    new_rule = {
                        "id": rule_id,
                        "name": rule_name,
                        "description": description,
                        "severity": severity,
                        "type": rule_type,
                        "pattern": pattern
                    }

                    st.session_state.policy["name"] = (
                        policy_name
                    )

                    st.session_state.policy["version"] = (
                        policy_version
                    )

                    st.session_state.policy["rules"].append(
                        new_rule
                    )

                    st.session_state.policy_json = json.dumps(
                        st.session_state.policy,
                        indent=2
                    )

                    st.session_state.last_result = None

                    add_audit(
                        "Policy rule added",
                        "INFO",
                        rule_id
                    )

                    st.success(
                        "Policy rule added. "
                        "Click REVALIDATE CODE."
                    )

                    st.rerun()


def terraform_section():
    st.header(
        "2. Terraform Code"
    )

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "SAFE DEMO",
            use_container_width=True
        ):

            load_demo("safe")
            st.rerun()

    with col2:

        if st.button(
            "UNSAFE DEMO",
            use_container_width=True
        ):

            load_demo("unsafe")
            st.rerun()

    uploaded_file = st.file_uploader(
        "Add your Terraform .tf file",
        type=["tf"]
    )

    if uploaded_file:

        try:

            uploaded_code = (
                uploaded_file
                .getvalue()
                .decode("utf-8")
            )

            st.session_state.filename = (
                uploaded_file.name
            )

            st.session_state.terraform_code = (
                uploaded_code
            )

            st.session_state.last_result = None

            add_audit(
                "Terraform file uploaded",
                "INFO",
                uploaded_file.name
            )

        except Exception as exc:

            st.error(
                f"Could not read file: {exc}"
            )

    filename = st.text_input(
        "Terraform filename",
        value=st.session_state.filename
    )

    st.session_state.filename = filename

    code = st.text_area(
        "Terraform Code",
        value=st.session_state.terraform_code,
        height=450
    )

    st.session_state.terraform_code = code

    st.write("")

    if st.button(
        "🔄 REVALIDATE CODE",
        type="primary",
        use_container_width=True
    ):

        with st.spinner(
            "Running Company Policy and Checkov validation..."
        ):

            validate_code()

        st.rerun()

    if st.session_state.last_result:

        report = json.dumps(
            st.session_state.last_result,
            indent=2,
            default=str
        )

        st.download_button(
            "Download Validation Report",
            data=report,
            file_name="iac_validation_report.json",
            mime="application/json",
            use_container_width=True
        )


def cvs_environment(cvs_root):
    env = os.environ.copy()

    if cvs_root:
        env["CVSROOT"] = cvs_root

    return env


def cvs_available():
    cvs = get_executable(
        "cvs"
    )

    if not cvs:

        return False, (
            "CVS executable was not found. "
            "Add cvs to packages.txt and redeploy."
        )

    rc, output = run_command(
        [
            cvs,
            "--version"
        ]
    )

    return rc == 0, output


def cvs_checkout(
    cvs_root,
    module,
    workspace
):
    cvs = get_executable(
        "cvs"
    )

    if not cvs:
        return 127, "CVS executable was not found."

    os.makedirs(
        workspace,
        exist_ok=True
    )

    command = [cvs]

    if cvs_root:

        command.extend(
            [
                "-d",
                cvs_root
            ]
        )

    command.extend(
        [
            "checkout",
            module
        ]
    )

    return run_command(
        command,
        cwd=workspace,
        env=cvs_environment(
            cvs_root
        )
    )


def cvs_update(
    cvs_root,
    workspace
):
    cvs = get_executable(
        "cvs"
    )

    if not cvs:
        return 127, "CVS executable was not found."

    return run_command(
        [
            cvs,
            "update",
            "-dP"
        ],
        cwd=workspace,
        env=cvs_environment(
            cvs_root
        )
    )


def cvs_add(
    cvs_root,
    workspace,
    filename
):
    cvs = get_executable(
        "cvs"
    )

    if not cvs:
        return 127, "CVS executable was not found."

    return run_command(
        [
            cvs,
            "add",
            filename
        ],
        cwd=workspace,
        env=cvs_environment(
            cvs_root
        )
    )


def cvs_diff(
    cvs_root,
    workspace,
    filename
):
    cvs = get_executable(
        "cvs"
    )

    if not cvs:
        return 127, "CVS executable was not found."

    return run_command(
        [
            cvs,
            "diff",
            "-u",
            filename
        ],
        cwd=workspace,
        env=cvs_environment(
            cvs_root
        )
    )


def cvs_commit(
    cvs_root,
    workspace,
    filename,
    message
):
    cvs = get_executable(
        "cvs"
    )

    if not cvs:
        return 127, "CVS executable was not found."

    return run_command(
        [
            cvs,
            "commit",
            "-m",
            message,
            filename
        ],
        cwd=workspace,
        env=cvs_environment(
            cvs_root
        )
    )


def cvs_log(
    cvs_root,
    workspace,
    filename
):
    cvs = get_executable(
        "cvs"
    )

    if not cvs:
        return 127, "CVS executable was not found."

    return run_command(
        [
            cvs,
            "log",
            filename
        ],
        cwd=workspace,
        env=cvs_environment(
            cvs_root
        )
    )


def cvs_save_workspace(workspace):

    os.makedirs(
        workspace,
        exist_ok=True
    )

    filename = st.session_state.filename

    if not filename.endswith(".tf"):
        filename += ".tf"

    path = os.path.join(
        workspace,
        filename
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            st.session_state.terraform_code
        )

    return path


def cvs_section():
    st.header(
        "3. CVS Version Control"
    )

    available, status = cvs_available()

    if available:

        st.success(
            "✓ CVS is installed."
        )

    else:

        st.warning(
            status
        )

    col1, col2 = st.columns(2)

    with col1:

        cvs_root = st.text_input(
            "CVSROOT",
            value=os.environ.get(
                "CVSROOT",
                ""
            )
        )

        cvs_module = st.text_input(
            "CVS Module"
        )

    with col2:

        default_workspace = os.path.join(
            tempfile.gettempdir(),
            "ai_iac_cvs"
        )

        workspace = st.text_input(
            "CVS Workspace",
            value=default_workspace
        )

        commit_message = st.text_input(
            "Commit Message",
            value="AI-IAC validated Terraform change"
        )

    col1, col2, col3 = st.columns(3)

    with col1:

        if st.button(
            "CVS CHECKOUT",
            use_container_width=True
        ):

            if not cvs_module:

                st.error(
                    "Enter a CVS Module."
                )

            else:

                rc, output = cvs_checkout(
                    cvs_root,
                    cvs_module,
                    workspace
                )

                st.session_state.cvs_output = output

                add_audit(
                    "CVS checkout",
                    "PASS" if rc == 0 else "FAIL",
                    output[-500:]
                )

                st.rerun()

    with col2:

        if st.button(
            "CVS UPDATE",
            use_container_width=True
        ):

            rc, output = cvs_update(
                cvs_root,
                workspace
            )

            st.session_state.cvs_output = output

            add_audit(
                "CVS update",
                "PASS" if rc == 0 else "FAIL",
                output[-500:]
            )

            st.rerun()

    with col3:

        if st.button(
            "CVS DIFF",
            use_container_width=True
        ):

            rc, output = cvs_diff(
                cvs_root,
                workspace,
                st.session_state.filename
            )

            st.session_state.cvs_output = output

            add_audit(
                "CVS diff",
                "PASS" if rc == 0 else "FAIL",
                output[-500:]
            )

            st.rerun()

    st.divider()

    if st.button(
        "🔐 VALIDATE + CVS COMMIT",
        type="primary",
        use_container_width=True
    ):

        result = st.session_state.last_result

        if result is None:
            result = validate_code()

        if result["failed"] > 0:

            st.error(
                "CVS COMMIT BLOCKED"
            )

            st.write(
                f"Passed: {result['passed']}"
            )

            st.write(
                f"Failed: {result['failed']}"
            )

            st.write(
                f"Skipped: {result['skipped']}"
            )

            st.write(
                "Fix the failed validation checks "
                "and click REVALIDATE CODE before committing."
            )

            add_audit(
                "CVS commit blocked",
                "FAIL",
                "Security validation failed."
            )

        else:

            if not available:

                st.error(
                    "CVS is not installed."
                )

            else:

                cvs_save_workspace(
                    workspace
                )

                update_rc, update_output = cvs_update(
                    cvs_root,
                    workspace
                )

                add_rc, add_output = cvs_add(
                    cvs_root,
                    workspace,
                    st.session_state.filename
                )

                diff_rc, diff_output = cvs_diff(
                    cvs_root,
                    workspace,
                    st.session_state.filename
                )

                commit_rc, commit_output = cvs_commit(
                    cvs_root,
                    workspace,
                    st.session_state.filename,
                    commit_message
                )

                st.session_state.cvs_output = (
                    "CVS UPDATE\n"
                    + update_output
                    + "\n\nCVS ADD\n"
                    + add_output
                    + "\n\nCVS DIFF\n"
                    + diff_output
                    + "\n\nCVS COMMIT\n"
                    + commit_output
                )

                if commit_rc == 0:

                    st.success(
                        "✓ Validation passed "
                        "and CVS commit completed."
                    )

                    add_audit(
                        "CVS commit",
                        "PASS",
                        commit_message
                    )

                else:

                    st.error(
                        "Validation passed, "
                        "but CVS commit failed."
                    )

                    add_audit(
                        "CVS commit",
                        "FAIL",
                        commit_output[-500:]
                    )

    if st.button(
        "CVS LOG",
        use_container_width=True
    ):

        rc, output = cvs_log(
            cvs_root,
            workspace,
            st.session_state.filename
        )

        st.session_state.cvs_output = output

        st.rerun()

    if st.session_state.cvs_output:

        st.subheader(
            "CVS Output"
        )

        st.text_area(
            "CVS command output",
            value=st.session_state.cvs_output,
            height=250,
            disabled=True
        )


def history_section():
    st.header(
        "4. Validation History"
    )

    if st.session_state.validation_history:

        st.dataframe(
            pd.DataFrame(
                st.session_state.validation_history
            ),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No validation history yet."
        )

    st.header(
        "5. Audit Log"
    )

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
    "🛡️ AI-IAC Security Configuration Validation"
)

st.caption(
    "Company Policy + Checkov + AI Remediation + Terraform + CVS"
)

policy_section()

st.divider()

terraform_section()

st.divider()

if st.session_state.last_result:

    show_validation_results(
        st.session_state.last_result
    )

else:

    st.info(
        "Select Safe Demo, Unsafe Demo, "
        "or upload a Terraform file, "
        "then click REVALIDATE CODE."
    )

st.divider()

cvs_section()

st.divider()

history_section()
