import streamlit as st
import subprocess
import shutil
import os
import re
from datetime import datetime

st.set_page_config(
    page_title="AI-IAC Configuration Validator",
    page_icon="🔐",
    layout="wide"
)

if "policy" not in st.session_state:
    st.session_state.policy = {
        "block_public_ssh": True,
        "trusted_ssh_cidr": "10.0.0.0/24",
        "block_public_rdp": True,
        "require_s3_public_access_block": True,
        "require_storage_encryption": True
    }

if "validation_history" not in st.session_state:
    st.session_state.validation_history = []

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "terraform_code" not in st.session_state:
    st.session_state.terraform_code = """resource "aws_security_group" "example" {
  name = "example"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "last_checkov_output" not in st.session_state:
    st.session_state.last_checkov_output = ""

if "last_policy_findings" not in st.session_state:
    st.session_state.last_policy_findings = []

if "cvs_result" not in st.session_state:
    st.session_state.cvs_result = ""

UNSAFE_TERRAFORM = """resource "aws_security_group" "example" {
  name = "example"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

SAFE_TERRAFORM = """resource "aws_security_group" "example" {
  name = "example"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
}
"""

def add_audit(message):
    st.session_state.audit_log.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": message
        }
    )

def get_checkov_path():
    return shutil.which("checkov")

def run_checkov(terraform_code):
    checkov_path = get_checkov_path()

    if not checkov_path:
        return False, "Checkov executable was not found. Install Checkov using the requirements.txt file."

    temp_file = "temporary_iac.tf"

    try:
        with open(temp_file, "w", encoding="utf-8") as file:
            file.write(terraform_code)

        result = subprocess.run(
            [
                checkov_path,
                "-f",
                temp_file,
                "--framework",
                "terraform"
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")

        passed = result.returncode == 0

        return passed, output

    except Exception as error:
        return False, str(error)

    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

def check_company_policy(terraform_code, policy):
    findings = []

    if policy["block_public_ssh"]:
        ssh_public_pattern = re.search(
            r"from_port\s*=\s*22[\s\S]{0,500}?cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"",
            terraform_code
        )

        if ssh_public_pattern:
            findings.append(
                "SSH port 22 is publicly accessible from 0.0.0.0/0."
            )

    if policy["block_public_rdp"]:
        rdp_public_pattern = re.search(
            r"from_port\s*=\s*3389[\s\S]{0,500}?cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"",
            terraform_code
        )

        if rdp_public_pattern:
            findings.append(
                "RDP port 3389 is publicly accessible from 0.0.0.0/0."
            )

    if policy["require_s3_public_access_block"]:
        if "aws_s3_bucket_public_access_block" not in terraform_code:
            if "aws_s3_bucket" in terraform_code:
                findings.append(
                    "S3 bucket public access block configuration is missing."
                )

    if policy["require_storage_encryption"]:
        storage_detected = (
            "aws_db_instance" in terraform_code
            or "aws_ebs_volume" in terraform_code
            or "aws_s3_bucket" in terraform_code
        )

        encryption_detected = (
            "encrypted = true" in terraform_code
            or "server_side_encryption_configuration" in terraform_code
            or "kms_key_id" in terraform_code
        )

        if storage_detected and not encryption_detected:
            findings.append(
                "Storage encryption configuration is missing."
            )

    return findings

def explain_findings(checkov_output, policy_findings):
    explanations = []

    if policy_findings:
        for finding in policy_findings:
            if "SSH port 22" in finding:
                explanations.append(
                    "SSH is exposed to the public internet. Restrict port 22 to the approved trusted network."
                )
            elif "RDP port 3389" in finding:
                explanations.append(
                    "RDP is exposed to the public internet. Restrict port 3389 to an approved internal network."
                )
            elif "S3 bucket public access" in finding:
                explanations.append(
                    "The S3 configuration does not contain the required public access block settings."
                )
            elif "Storage encryption" in finding:
                explanations.append(
                    "The storage resource should use encryption to protect stored data."
                )

    if not explanations and checkov_output:
        if "FAILED" in checkov_output.upper():
            explanations.append(
                "Checkov identified one or more infrastructure security checks that require attention."
            )

    if not explanations:
        explanations.append(
            "No company-policy explanation is required because the current configuration passed the configured policy checks."
        )

    return explanations

def suggest_correction(terraform_code, policy_findings):
    corrected_code = terraform_code

    if any("SSH port 22" in finding for finding in policy_findings):
        corrected_code = re.sub(
            r'from_port\s*=\s*22([\s\S]{0,300}?)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            r'from_port = 22\1cidr_blocks = ["10.0.0.0/24"]',
            corrected_code
        )

    if any("RDP port 3389" in finding for finding in policy_findings):
        corrected_code = re.sub(
            r'\n\s*ingress\s*\{\s*from_port\s*=\s*3389[\s\S]*?\n\s*\}',
            "",
            corrected_code,
            flags=re.MULTILINE
        )

    return corrected_code

def cvs_available():
    return shutil.which("cvs") is not None

def run_cvs_command(arguments, workspace=None):
    cvs_path = shutil.which("cvs")

    if not cvs_path:
        return False, "CVS executable was not found on this system."

    try:
        result = subprocess.run(
            [cvs_path] + arguments,
            cwd=workspace if workspace else None,
            capture_output=True,
            text=True,
            timeout=120
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")

        return result.returncode == 0, output

    except Exception as error:
        return False, str(error)

def cvs_checkout(repository, module, workspace):
    os.makedirs(workspace, exist_ok=True)

    return run_cvs_command(
        [
            "-d",
            repository,
            "checkout",
            module
        ],
        workspace
    )

def cvs_update(repository, workspace):
    return run_cvs_command(
        [
            "-d",
            repository,
            "update",
            "-dP"
        ],
        workspace
    )

def cvs_history(repository, module):
    return run_cvs_command(
        [
            "-d",
            repository,
            "log",
            module
        ]
    )

def cvs_commit(repository, workspace, message):
    return run_cvs_command(
        [
            "-d",
            repository,
            "commit",
            "-m",
            message
        ],
        workspace
    )

st.title("🔐 AI-IAC Configuration Validator")
st.write(
    "Validate Terraform Infrastructure as Code against company security policies and Checkov before CVS commit."
)

st.sidebar.header("Company Security Policy")

block_public_ssh = st.sidebar.checkbox(
    "Block public SSH",
    value=st.session_state.policy["block_public_ssh"]
)

trusted_ssh_cidr = st.sidebar.text_input(
    "Trusted SSH CIDR",
    value=st.session_state.policy["trusted_ssh_cidr"]
)

block_public_rdp = st.sidebar.checkbox(
    "Block public RDP",
    value=st.session_state.policy["block_public_rdp"]
)

require_s3_public_access_block = st.sidebar.checkbox(
    "Require S3 public access block",
    value=st.session_state.policy["require_s3_public_access_block"]
)

require_storage_encryption = st.sidebar.checkbox(
    "Require storage encryption",
    value=st.session_state.policy["require_storage_encryption"]
)

if st.sidebar.button("Save Policy Baseline"):
    st.session_state.policy = {
        "block_public_ssh": block_public_ssh,
        "trusted_ssh_cidr": trusted_ssh_cidr,
        "block_public_rdp": block_public_rdp,
        "require_s3_public_access_block": require_s3_public_access_block,
        "require_storage_encryption": require_storage_encryption
    }

    add_audit("Company security policy baseline updated.")
    st.sidebar.success("Policy baseline saved.")

st.sidebar.subheader("Active Policy")

st.sidebar.write(
    {
        "Public SSH blocked": st.session_state.policy["block_public_ssh"],
        "Trusted SSH network": st.session_state.policy["trusted_ssh_cidr"],
        "Public RDP blocked": st.session_state.policy["block_public_rdp"],
        "S3 public access block": st.session_state.policy["require_s3_public_access_block"],
        "Storage encryption": st.session_state.policy["require_storage_encryption"]
    }
)

st.sidebar.subheader("CVS Configuration")

cvs_repository = st.sidebar.text_input(
    "CVS Repository",
    value="C:/cvsrepo"
)

cvs_module = st.sidebar.text_input(
    "CVS Module",
    value="iac-project"
)

cvs_workspace = st.sidebar.text_input(
    "CVS Workspace",
    value="C:/cvsworkspace"
)

tabs = st.tabs(
    [
        "Terraform Validation",
        "Policy",
        "CVS",
        "Validation History",
        "Audit Log"
    ]
)

with tabs[0]:

    st.header("Terraform Infrastructure Code")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Load Unsafe Demo"):
            st.session_state.terraform_code = UNSAFE_TERRAFORM
            add_audit("Unsafe Terraform demonstration loaded.")

    with col2:
        if st.button("Load Safe Demo"):
            st.session_state.terraform_code = SAFE_TERRAFORM
            add_audit("Safe Terraform demonstration loaded.")

    uploaded_file = st.file_uploader(
        "Upload Terraform file",
        type=["tf"]
    )

    if uploaded_file:
        st.session_state.terraform_code = uploaded_file.read().decode(
            "utf-8",
            errors="replace"
        )

        add_audit(
            "Terraform file uploaded: " + uploaded_file.name
        )

    st.session_state.terraform_code = st.text_area(
        "Terraform Code",
        value=st.session_state.terraform_code,
        height=450
    )

    if st.button("Validate Terraform", type="primary"):

        with st.spinner("Running Checkov and company policy validation..."):

            checkov_passed, checkov_output = run_checkov(
                st.session_state.terraform_code
            )

            policy_findings = check_company_policy(
                st.session_state.terraform_code,
                st.session_state.policy
            )

            overall_passed = checkov_passed and not policy_findings

            st.session_state.last_result = overall_passed
            st.session_state.last_checkov_output = checkov_output
            st.session_state.last_policy_findings = policy_findings

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            st.session_state.validation_history.insert(
                0,
                {
                    "time": timestamp,
                    "result": "PASSED" if overall_passed else "FAILED",
                    "checkov": "PASSED" if checkov_passed else "FAILED",
                    "policy": "PASSED" if not policy_findings else "FAILED"
                }
            )

            add_audit(
                "Terraform validation completed: "
                + ("PASSED" if overall_passed else "FAILED")
            )

    if st.session_state.last_result is not None:

        if st.session_state.last_result:
            st.success("✅ VALIDATION PASSED")
        else:
            st.error("❌ VALIDATION FAILED")

        result_col1, result_col2 = st.columns(2)

        with result_col1:
            st.subheader("Checkov Result")

            if "last_checkov_output" in st.session_state:
                if st.session_state.last_checkov_output:
                    st.code(
                        st.session_state.last_checkov_output,
                        language="text"
                    )

        with result_col2:
            st.subheader("Company Policy Result")

            if st.session_state.last_policy_findings:
                for finding in st.session_state.last_policy_findings:
                    st.error(finding)
            else:
                st.success("All configured company policies passed.")

        st.subheader("AI Explanation")

        explanations = explain_findings(
            st.session_state.last_checkov_output,
            st.session_state.last_policy_findings
        )

        for explanation in explanations:
            st.info(explanation)

        if st.session_state.last_policy_findings:

            st.subheader("Suggested Correction")

            corrected_code = suggest_correction(
                st.session_state.terraform_code,
                st.session_state.last_policy_findings
            )

            st.code(
                corrected_code,
                language="hcl"
            )

            if st.button("Use Suggested Correction"):

                st.session_state.terraform_code = corrected_code

                add_audit(
                    "Suggested Terraform correction applied."
                )

                st.rerun()

with tabs[1]:

    st.header("Company Policy Baseline")

    policy_table = {
        "Policy": [
            "Block public SSH",
            "Trusted SSH CIDR",
            "Block public RDP",
            "Require S3 public access block",
            "Require storage encryption"
        ],
        "Value": [
            str(st.session_state.policy["block_public_ssh"]),
            st.session_state.policy["trusted_ssh_cidr"],
            str(st.session_state.policy["block_public_rdp"]),
            str(st.session_state.policy["require_s3_public_access_block"]),
            str(st.session_state.policy["require_storage_encryption"])
        ]
    }

    st.table(policy_table)

    st.write(
        "The company security team defines the baseline policy. Developers validate their project-specific Terraform configuration against this baseline."
    )

with tabs[2]:

    st.header("CVS Version Control")

    if cvs_available():
        st.success("CVS executable detected on this system.")
    else:
        st.warning(
            "CVS executable is not available in this Streamlit environment. "
            "CVS operations can be demonstrated when the application runs on a machine with CVS installed and a reachable CVS repository."
        )

    st.subheader("CVS Checkout")

    if st.button("CVS Checkout"):
        success, output = cvs_checkout(
            cvs_repository,
            cvs_module,
            cvs_workspace
        )

        st.session_state.cvs_result = output

        if success:
            st.success("CVS checkout completed.")
            add_audit("CVS checkout completed.")
        else:
            st.error("CVS checkout failed.")

        st.code(output, language="text")

    st.subheader("CVS Update")

    if st.button("CVS Update"):
        success, output = cvs_update(
            cvs_repository,
            cvs_workspace
        )

        st.session_state.cvs_result = output

        if success:
            st.success("CVS update completed.")
            add_audit("CVS update completed.")
        else:
            st.error("CVS update failed.")

        st.code(output, language="text")

    st.subheader("CVS History")

    if st.button("View CVS History"):
        success, output = cvs_history(
            cvs_repository,
            cvs_module
        )

        st.session_state.cvs_result = output

        if success:
            st.success("CVS history retrieved.")
            add_audit("CVS history viewed.")
        else:
            st.error("Unable to retrieve CVS history.")

        st.code(output, language="text")

    st.subheader("Security-Gated CVS Commit")

    commit_message = st.text_input(
        "Commit Message",
        value="Validated Terraform configuration"
    )

    if st.button("Validate and CVS Commit"):

        with st.spinner("Validating before CVS commit..."):

            checkov_passed, checkov_output = run_checkov(
                st.session_state.terraform_code
            )

            policy_findings = check_company_policy(
                st.session_state.terraform_code,
                st.session_state.policy
            )

            validation_passed = checkov_passed and not policy_findings

        if not validation_passed:

            st.error(
                "CVS COMMIT BLOCKED: Terraform validation failed."
            )

            if policy_findings:
                for finding in policy_findings:
                    st.error(finding)

            st.code(checkov_output, language="text")

            add_audit(
                "CVS commit blocked because validation failed."
            )

        else:

            st.success(
                "Terraform validation passed. CVS commit is allowed."
            )

            success, output = cvs_commit(
                cvs_repository,
                cvs_workspace,
                commit_message
            )

            if success:
                st.success("CVS commit completed successfully.")
                add_audit(
                    "CVS commit completed after successful validation."
                )
            else:
                st.error("CVS commit failed.")
                st.code(output, language="text")

with tabs[3]:

    st.header("Validation History")

    if not st.session_state.validation_history:
        st.info("No validation history available yet.")
    else:
        st.table(st.session_state.validation_history)

with tabs[4]:

    st.header("Audit Log")

    if not st.session_state.audit_log:
        st.info("No audit events recorded yet.")
    else:
        st.table(st.session_state.audit_log)

st.divider()

st.caption(
    "AI-IAC Configuration Validator | Streamlit + Python + Terraform + Checkov + Company Policy + CVS"
)
