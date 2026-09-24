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


SAFE_DEMO = """terraform {
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


UNSAFE_DEMO = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "unsafe_demo" {
  name        = "unsafe-demo"

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
"""


DEFAULT_POLICY = {
    "name": "Company Security Policy",
    "version": "1.0",
    "rules": [
        {
            "id": "POLICY-SSH-001",
            "name": "No Public SSH",
            "description": "SSH must not be accessible from the public internet",
            "severity": "HIGH",
            "type": "public_ssh"
        },
        {
            "id": "POLICY-SSH-002",
            "name": "SSH Port Must Be 22",
            "description": "SSH ingress must use port 22",
            "severity": "MEDIUM",
            "type": "ssh_port"
        },
        {
            "id": "POLICY-DESC-001",
            "name": "Security Group Needs Description",
            "description": "Security groups must have a description",
            "severity": "MEDIUM",
            "type": "security_group_description"
        }
    ]
}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def initialize_state():
    defaults = {
        "terraform_code": SAFE_DEMO,
        "filename": "safe_demo.tf",
        "policy": json.loads(json.dumps(DEFAULT_POLICY)),
        "policy_json": json.dumps(DEFAULT_POLICY, indent=2),
        "last_result": None,
        "suggested_code": "",
        "ai_explanation": "",
        "validation_history": [],
        "audit_log": [],
        "cvs_output": ""
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_state()


def audit(event, status="INFO", details=""):
    st.session_state.audit_log.insert(
        0,
        {
            "Time": now(),
            "Event": event,
            "Status": status,
            "Details": details
        }
    )

    st.session_state.audit_log = (
        st.session_state.audit_log[:100]
    )


def executable(name):
    return shutil.which(name)


def command_run(command, cwd=None, env=None, timeout=180):
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


def run_checkov(code, filename):
    checkov_path = executable("checkov")

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

        return_code, output = command_run(
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
                "error": (
                    "Checkov did not return readable JSON."
                ),
                "raw_output": output
            }

        results = data.get(
            "results",
            {}
        )

        passed = [
            checkov_item(
                item,
                "Checkov"
            )
            for item in (
                results.get(
                    "passed_checks",
                    []
                ) or []
            )
        ]

        failed = [
            checkov_item(
                item,
                "Checkov"
            )
            for item in (
                results.get(
                    "failed_checks",
                    []
                ) or []
            )
        ]

        skipped = [
            checkov_item(
                item,
                "Checkov"
            )
            for item in (
                results.get(
                    "skipped_checks",
                    []
                ) or []
            )
        ]

        return {
            "available": True,
            "return_code": return_code,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "error": "",
            "raw_output": output
        }


def policy_rule_result(rule, code):
    rule_id = rule.get(
        "id",
        "POLICY-UNKNOWN"
    )

    name = rule.get(
        "name",
        rule_id
    )

    severity = rule.get(
        "severity",
        "MEDIUM"
    )

    description = rule.get(
        "description",
        ""
    )

    rule_type = rule.get(
        "type",
        ""
    )

    base = {
        "id": rule_id,
        "name": name,
        "description": description,
        "severity": severity,
        "type": "Company Policy"
    }

    if rule_type == "public_ssh":

        public_ssh = re.search(
            r'from_port\s*=\s*22[\s\S]*?to_port\s*=\s*22[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            code
        )

        if public_ssh:
            return None, {
                **base,
                "reason": (
                    "SSH port 22 is accessible from "
                    "0.0.0.0/0."
                )
            }

        return base, None

    if rule_type == "ssh_port":

        ssh_blocks = re.findall(
            r'ingress\s*\{([\s\S]*?)\}',
            code
        )

        ssh_found = False

        for block in ssh_blocks:

            from_match = re.search(
                r'from_port\s*=\s*(\d+)',
                block
            )

            to_match = re.search(
                r'to_port\s*=\s*(\d+)',
                block
            )

            if from_match and to_match:

                if (
                    from_match.group(1) == "22"
                    and
                    to_match.group(1) == "22"
                ):
                    ssh_found = True

        if ssh_found:
            return base, None

        return None, {
            **base,
            "reason": (
                "SSH ingress must use from_port 22 "
                "and to_port 22."
            )
        }

    if rule_type == "security_group_description":

        security_groups = re.findall(
            r'resource\s+"aws_security_group"\s+"[^"]+"\s*\{([\s\S]*?)\n\}',
            code
        )

        if not security_groups:
            return base, None

        for block in security_groups:

            if re.search(
                r'^\s*description\s*=',
                block,
                re.MULTILINE
            ):
                return base, None

        return None, {
            **base,
            "reason": (
                "The AWS security group does not "
                "contain a description."
            )
        }

    pattern = rule.get(
        "pattern",
        ""
    )

    if pattern:

        if rule.get("type") == "forbidden_text":

            if pattern in code:
                return None, {
                    **base,
                    "reason": (
                        f"Forbidden text found: {pattern}"
                    )
                }

            return base, None

        if rule.get("type") == "required_text":

            if pattern in code:
                return base, None

            return None, {
                **base,
                "reason": (
                    f"Required text not found: {pattern}"
                )
            }

        if rule.get("type") == "regex":

            try:

                matched = re.search(
                    pattern,
                    code,
                    re.MULTILINE
                )

                if matched:
                    return base, None

                return None, {
                    **base,
                    "reason": (
                        f"Regex condition failed: {pattern}"
                    )
                }

            except re.error as exc:

                return None, {
                    **base,
                    "reason": (
                        f"Invalid regex: {exc}"
                    )
                }

    return None, {
        **base,
        "reason": "Unsupported policy rule."
    }


def run_company_policy(code):
    passed = []
    failed = []

    for rule in st.session_state.policy.get(
        "rules",
        []
    ):

        good, bad = policy_rule_result(
            rule,
            code
        )

        if good:
            passed.append(good)

        if bad:
            failed.append(bad)

    return passed, failed


def validate_code():
    code = st.session_state.terraform_code

    filename = (
        st.session_state.filename
        or "main.tf"
    )

    if not filename.endswith(".tf"):
        filename += ".tf"

    policy_passed, policy_failed = (
        run_company_policy(code)
    )

    checkov = run_checkov(
        code,
        filename
    )

    passed = (
        policy_passed
        + checkov["passed"]
    )

    failed = (
        policy_failed
        + checkov["failed"]
    )

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
        "time": now(),
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

    if result["failed"] == 0:

        st.session_state.suggested_code = ""
        st.session_state.ai_explanation = ""

    add_audit(
        "Validation completed",
        overall,
        (
            f"Passed={result['passed']}, "
            f"Failed={result['failed']}, "
            f"Skipped={result['skipped']}"
        )
    )

    st.session_state.validation_history.insert(
        0,
        {
            "Time": result["time"],
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

    return result


def generate_corrected_code(code, result):
    corrected = code

    failures = result.get(
        "failed_checks",
        []
    )

    explanations = []

    for failure in failures:

        failure_text = (
            str(failure.get("name", ""))
            + " "
            + str(failure.get("reason", ""))
            + " "
            + str(failure.get("guideline", ""))
        ).lower()

        if (
            "public ssh" in failure_text
            or "0.0.0.0/0" in failure_text
            or (
                "ssh" in failure_text
                and "public" in failure_text
            )
        ):

            corrected = re.sub(
                r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                'cidr_blocks = ["10.0.0.0/24"]',
                corrected
            )

            explanations.append(
                "Restricted public SSH access to "
                "10.0.0.0/24."
            )

        if (
            "description" in failure_text
            and "security group" in failure_text
        ):

            pattern = (
                r'(resource\s+"aws_security_group"\s+"[^"]+"\s*\{\s*'
                r'name\s*=\s*"[^"]+"\s*)'
            )

            replacement = (
                r'\1\n'
                r'  description = '
                r'"Security group managed by company policy"\n'
            )

            corrected = re.sub(
                pattern,
                replacement,
                corrected,
                count=1
            )

            explanations.append(
                "Added a security group description."
            )

        if (
            "ssh port" in failure_text
            or "port must be 22" in failure_text
        ):

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

            explanations.append(
                "Changed SSH ingress to port 22."
            )

        if failure.get("type") == "Company Policy":

            if failure.get("id") == "POLICY-SSH-001":

                corrected = corrected.replace(
                    'cidr_blocks = ["0.0.0.0/0"]',
                    'cidr_blocks = ["10.0.0.0/24"]'
                )

                explanations.append(
                    "Company policy requires SSH "
                    "to use an approved network."
                )

            if failure.get("id") == "POLICY-DESC-001":

                if "resource \"aws_security_group\"" in corrected:

                    corrected = re.sub(
                        r'(name\s*=\s*"[^"]+"\n)',
                        r'\1  description = "Managed security group"\n',
                        corrected,
                        count=1
                    )

                    explanations.append(
                        "Added the required security "
                        "group description."
                    )

    if corrected == code:

        corrected = code.replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/24"]'
        )

        explanations.append(
            "Restricted public network access."
        )

    st.session_state.ai_explanation = "\n".join(
        dict.fromkeys(explanations)
    )

    return corrected


def load_demo(name):

    if name == "safe":

        st.session_state.terraform_code = SAFE_DEMO
        st.session_state.filename = "safe_demo.tf"

    else:

        st.session_state.terraform_code = UNSAFE_DEMO
        st.session_state.filename = "unsafe_demo.tf"

    st.session_state.last_result = None
    st.session_state.suggested_code = ""
    st.session_state.ai_explanation = ""

    audit(
        "Demo loaded",
        "INFO",
        name
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

    st.subheader(
        "Current Policy Rules"
    )

    rows = []

    for rule in policy.get(
        "rules",
        []
    ):

        rows.append(
            {
                "ID": rule.get("id", ""),
                "Name": rule.get("name", ""),
                "Severity": rule.get("severity", ""),
                "Type": rule.get("type", "")
            }
        )

    if rows:

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True
        )

    with st.expander(
        "✏️ Edit Complete Policy"
    ):

        policy_json = st.text_area(
            "Policy JSON",
            value=st.session_state.policy_json,
            height=350
        )

        if st.button(
            "Save Policy",
            key="save_policy"
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

                audit(
                    "Security policy updated",
                    "INFO"
                )

                st.success(
                    "Policy updated successfully."
                )

            except Exception as exc:

                st.error(
                    f"Invalid policy JSON: {exc}"
                )

    with st.expander(
        "➕ Add New Policy Rule"
    ):

        with st.form(
            "add_rule_form"
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

                    rule = {
                        "id": rule_id,
                        "name": rule_name,
                        "description": description,
                        "severity": severity,
                        "type": rule_type,
                        "pattern": pattern
                    }

                    st.session_state.policy[
                        "name"
                    ] = policy_name

                    st.session_state.policy[
                        "version"
                    ] = policy_version

                    st.session_state.policy[
                        "rules"
                    ].append(
                        rule
                    )

                    st.session_state.policy_json = json.dumps(
                        st.session_state.policy,
                        indent=2
                    )

                    st.session_state.last_result = None

                    audit(
                        "Policy rule added",
                        "INFO",
                        rule_id
                    )

                    st.success(
                        "New policy rule added."
                    )

                    st.rerun()


def terraform_section():

    st.header(
        "2. Terraform Code"
    )

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "🟢 SAFE DEMO",
            use_container_width=True
        ):

            load_demo("safe")
            st.rerun()

    with col2:

        if st.button(
            "🔴 UNSAFE DEMO",
            use_container_width=True
        ):

            load_demo("unsafe")
            st.rerun()

    uploaded_file = st.file_uploader(
        "📤 Add your Terraform .tf file",
        type=["tf"]
    )

    if uploaded_file:

        try:

            content = (
                uploaded_file
                .getvalue()
                .decode("utf-8")
            )

            st.session_state.filename = (
                uploaded_file.name
            )

            st.session_state.terraform_code = content

            st.session_state.last_result = None
            st.session_state.suggested_code = ""

            audit(
                "Terraform file uploaded",
                "INFO",
                uploaded_file.name
            )

        except Exception as exc:

            st.error(
                f"Could not read file: {exc}"
            )

    st.session_state.filename = st.text_input(
        "Terraform filename",
        value=st.session_state.filename
    )

    st.session_state.terraform_code = st.text_area(
        "Terraform Code",
        value=st.session_state.terraform_code,
        height=450
    )

    if st.button(
        "🔄 REVALIDATE CODE",
        type="primary",
        use_container_width=True
    ):

        with st.spinner(
            "Running Company Policy and Checkov..."
        ):

            validate_code()

        st.rerun()


def results_section():

    result = st.session_state.last_result

    if not result:

        st.info(
            "Load a demo or upload Terraform, "
            "then click REVALIDATE CODE."
        )

        return

    st.header(
        "3. Validation Results"
    )

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

    if result["overall"] == "PASS":

        st.success(
            "🎉 ALL CHECKS PASSED"
        )

    else:

        st.error(
            f"❌ {result['failed']} CHECK(S) FAILED"
        )

    st.write(
        f"File: `{result['filename']}`"
    )

    st.write(
        f"Validated: `{result['time']}`"
    )

    passed_tab, failed_tab, skipped_tab = st.tabs(
        [
            f"✅ Passed ({result['passed']})",
            f"❌ Failed ({result['failed']})",
            f"⏭ Skipped ({result['skipped']})"
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
                        "Severity": item.get(
                            "severity",
                            ""
                        )
                    }
                )

            st.dataframe(
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "No passed checks."
            )

    with failed_tab:

        if not result["failed_checks"]:

            st.success(
                "No failed checks."
            )

        else:

            rows = []

            for item in result["failed_checks"]:

                rows.append(
                    {
                        "ID": item.get("id", ""),
                        "Check": item.get("name", ""),
                        "Severity": item.get(
                            "severity",
                            ""
                        ),
                        "Type": item.get(
                            "type",
                            ""
                        ),
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
                pd.DataFrame(rows),
                use_container_width=True,
                hide_index=True
            )

            st.divider()

            st.subheader(
                "🤖 AI Security Remediation"
            )

            st.write(
                f"{result['failed']} failed check(s) "
                "were detected."
            )

            if st.button(
                "🤖 GENERATE CORRECTED CODE",
                type="primary",
                use_container_width=True
            ):

                with st.spinner(
                    "AI is analyzing the failed checks..."
                ):

                    corrected = generate_corrected_code(
                        st.session_state.terraform_code,
                        result
                    )

                    st.session_state.suggested_code = corrected

                audit(
                    "AI corrected code generated",
                    "INFO",
                    f"{result['failed']} failed checks"
                )

                st.rerun()

            if st.session_state.suggested_code:

                st.subheader(
                    "🤖 Suggested Corrected Terraform"
                )

                if st.session_state.ai_explanation:

                    st.info(
                        st.session_state.ai_explanation
                    )

                st.code(
                    st.session_state.suggested_code,
                    language="hcl"
                )

                col1, col2 = st.columns(2)

                with col1:

                    if st.button(
                        "✅ APPLY CORRECTED CODE",
                        type="primary",
                        use_container_width=True
                    ):

                        st.session_state.terraform_code = (
                            st.session_state.suggested_code
                        )

                        st.session_state.last_result = None

                        audit(
                            "Corrected code applied",
                            "INFO"
                        )

                        st.success(
                            "Corrected code applied. "
                            "Click REVALIDATE CODE."
                        )

                        st.rerun()

                with col2:

                    if st.button(
                        "🔄 REVALIDATE NOW",
                        use_container_width=True
                    ):

                        validate_code()

                        st.rerun()

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


def cvs_environment(cvs_root):

    env = os.environ.copy()

    if cvs_root:

        env["CVSROOT"] = cvs_root

    return env


def cvs_available():

    cvs = executable(
        "cvs"
    )

    if not cvs:

        return False, (
            "CVS executable was not found."
        )

    rc, output = command_run(
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

    cvs = executable(
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

    return command_run(
        command,
        cwd=workspace,
        env=cvs_environment(cvs_root)
    )


def cvs_update(
    cvs_root,
    workspace
):

    cvs = executable(
        "cvs"
    )

    if not cvs:

        return 127, "CVS executable was not found."

    return command_run(
        [
            cvs,
            "update",
            "-dP"
        ],
        cwd=workspace,
        env=cvs_environment(cvs_root)
    )


def cvs_diff(
    cvs_root,
    workspace,
    filename
):

    cvs = executable(
        "cvs"
    )

    if not cvs:

        return 127, "CVS executable was not found."

    return command_run(
        [
            cvs,
            "diff",
            "-u",
            filename
        ],
        cwd=workspace,
        env=cvs_environment(cvs_root)
    )


def cvs_add(
    cvs_root,
    workspace,
    filename
):

    cvs = executable(
        "cvs"
    )

    if not cvs:

        return 127, "CVS executable was not found."

    return command_run(
        [
            cvs,
            "add",
            filename
        ],
        cwd=workspace,
        env=cvs_environment(cvs_root)
    )


def cvs_commit(
    cvs_root,
    workspace,
    filename,
    message
):

    cvs = executable(
        "cvs"
    )

    if not cvs:

        return 127, "CVS executable was not found."

    return command_run(
        [
            cvs,
            "commit",
            "-m",
            message,
            filename
        ],
        cwd=workspace,
        env=cvs_environment(cvs_root)
    )


def cvs_log(
    cvs_root,
    workspace,
    filename
):

    cvs = executable(
        "cvs"
    )

    if not cvs:

        return 127, "CVS executable was not found."

    return command_run(
        [
            cvs,
            "log",
            filename
        ],
        cwd=workspace,
        env=cvs_environment(cvs_root)
    )


def cvs_section():

    st.header(
        "4. CVS Version Control"
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

        workspace = st.text_input(
            "CVS Workspace",
            value=os.path.join(
                tempfile.gettempdir(),
                "ai_iac_cvs"
            )
        )

        message = st.text_input(
            "Commit Message",
            value="AI-IAC validated Terraform change"
        )

    c1, c2, c3 = st.columns(3)

    with c1:

        if st.button(
            "CVS CHECKOUT",
            use_container_width=True
        ):

            if not cvs_module:

                st.error(
                    "Enter CVS Module."
                )

            else:

                rc, output = cvs_checkout(
                    cvs_root,
                    cvs_module,
                    workspace
                )

                st.session_state.cvs_output = output

                audit(
                    "CVS checkout",
                    "PASS" if rc == 0 else "FAIL",
                    output[-500:]
                )

                st.rerun()

    with c2:

        if st.button(
            "CVS UPDATE",
            use_container_width=True
        ):

            rc, output = cvs_update(
                cvs_root,
                workspace
            )

            st.session_state.cvs_output = output

            audit(
                "CVS update",
                "PASS" if rc == 0 else "FAIL",
                output[-500:]
            )

            st.rerun()

    with c3:

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

            audit(
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
                "Fix the failed checks and "
                "revalidate before committing."
            )

        elif not available:

            st.error(
                "CVS is not installed."
            )

        else:

            os.makedirs(
                workspace,
                exist_ok=True
            )

            filename = st.session_state.filename

            if not filename.endswith(".tf"):
                filename += ".tf"

            file_path = os.path.join(
                workspace,
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

            update_rc, update_output = cvs_update(
                cvs_root,
                workspace
            )

            add_rc, add_output = cvs_add(
                cvs_root,
                workspace,
                filename
            )

            diff_rc, diff_output = cvs_diff(
                cvs_root,
                workspace,
                filename
            )

            commit_rc, commit_output = cvs_commit(
                cvs_root,
                workspace,
                filename,
                message
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
                    "✓ Validation passed and "
                    "CVS commit completed."
                )

                audit(
                    "CVS commit",
                    "PASS",
                    message
                )

            else:

                st.error(
                    "Validation passed, but "
                    "CVS commit failed."
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
        "5. Validation History"
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
        "6. Audit Log"
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

results_section()

st.divider()

cvs_section()

st.divider()

history_section()
