#!/usr/bin/env python3

import subprocess
import json
import csv
import argparse
import logging
import sys
from datetime import datetime

# --- Configuration ---
# Adjust severity levels if needed
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def run_cmd(cmd, profile=None, context=None, check_rc=True, suppress_error=False):
    """
    Runs a shell command, optionally injecting AWS profile and kubectl context.
    Returns its stdout.
    """
    # Inject context/profile if provided
    if cmd.strip().startswith("kubectl ") and context:
        cmd = f"kubectl --context {context} {cmd[len('kubectl '):]}"
    elif cmd.strip().startswith("aws ") and profile:
        cmd = f"aws --profile {profile} {cmd[len('aws '):]}"

    logging.debug(f"Running command: {cmd}")
    try:
        # Using shell=True is convenient but be mindful of security if commands were constructed from external input.
        # For this tool's purpose (running known aws/kubectl commands), it's generally acceptable.
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check_rc, encoding='utf-8')
        return result.stdout.strip()
    except FileNotFoundError:
        logging.error(f"Command not found (ensure kubectl/aws CLI is installed and in PATH): {cmd.split()[0]}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if not suppress_error:
            stderr_output = e.stderr.strip() if e.stderr else "(no stderr)"
            logging.error(f"Command failed (rc={e.returncode}): {cmd}")
            logging.error(f"Stderr: {stderr_output}")
        return None # Indicate failure

def parse_json(json_string, cmd_for_error=""):
    """Safely parses a JSON string."""
    if not json_string:
        return None
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON output from command '{cmd_for_error}': {e}")
        logging.debug(f"Invalid JSON string: {json_string[:500]}...") # Log snippet
        return None

def add_finding(findings_list, severity, finding_type, details, recommendation, reference, namespace, name, asset_type="Kubernetes Resource"):
    """Helper to structure and add a finding."""
    findings_list.append({
        'severity': severity,
        'type': finding_type,
        'namespace': namespace if namespace else '(cluster)',
        'name': name,
        'asset_type': asset_type,
        'details': details,
        'recommendation': recommendation,
        'reference': reference
    })

# --- Kubernetes Resource Fetching Functions ---

def get_k8s_resources(resource_type, context=None, namespace=None, use_all_namespaces=False):
    """Fetches Kubernetes resources of a specific type using the specified context."""
    namespace_flag = f"-n {namespace}" if namespace else ""
    all_namespaces_flag = "--all-namespaces" if use_all_namespaces else ""
    cmd = f"kubectl get {resource_type} {namespace_flag} {all_namespaces_flag} -o json"
    # Pass context to run_cmd
    output = run_cmd(cmd, context=context, suppress_error=True) # Suppress error here, handle None below
    if output is None:
        logging.warning(f"Could not retrieve {resource_type}s (context: {context or 'default'}). Skipping checks.")
        return []
    data = parse_json(output, cmd)
    return data.get('items', []) if data else []

# --- AWS Resource Fetching Functions ---

def get_aws_eks_cluster_info(cluster_name, region, profile=None):
    """Fetches EKS cluster description using the specified profile."""
    cmd = f"aws eks describe-cluster --name {cluster_name} --region {region} --output json"
    # Pass profile to run_cmd
    output = run_cmd(cmd, profile=profile)
    if not output:
        logging.error(f"Failed to describe EKS cluster '{cluster_name}' in region '{region}' (profile: {profile or 'default'}). Check AWS credentials and permissions.")
        return None
    data = parse_json(output, cmd)
    return data.get('cluster') if data else None

def get_aws_eks_nodegroups(cluster_name, region, profile=None):
    """Lists and describes EKS nodegroups using the specified profile."""
    nodegroups = []
    cmd_list = f"aws eks list-nodegroups --cluster-name {cluster_name} --region {region} --output json"
    # Pass profile to run_cmd
    output_list = run_cmd(cmd_list, profile=profile)
    data_list = parse_json(output_list, cmd_list)
    if not data_list or not data_list.get('nodegroups'):
        logging.info(f"No managed nodegroups found (profile: {profile or 'default'}).")
        # Consider checking for self-managed nodes via EC2 tags if needed
        return nodegroups

    for ng_name in data_list['nodegroups']:
        cmd_desc = f"aws eks describe-nodegroup --cluster-name {cluster_name} --nodegroup-name {ng_name} --region {region} --output json"
        # Pass profile to run_cmd
        output_desc = run_cmd(cmd_desc, profile=profile)
        data_desc = parse_json(output_desc, cmd_desc)
        if data_desc and data_desc.get('nodegroup'):
            nodegroups.append(data_desc['nodegroup'])
        else:
            logging.warning(f"Could not describe nodegroup '{ng_name}' (profile: {profile or 'default'}).")
    return nodegroups

def get_aws_ec2_instance_metadata_options(instance_id, region, profile=None):
    """Checks EC2 instance metadata options (IMDSv2) using the specified profile."""
    # This requires permission to describe instances, might not always be available with read-only EKS access
    cmd = f"aws ec2 describe-instances --instance-ids {instance_id} --region {region} --query 'Reservations[*].Instances[*].MetadataOptions' --output json"
    # Pass profile to run_cmd
    output = run_cmd(cmd, profile=profile, suppress_error=True) # Often fails due to permissions
    if output:
        data = parse_json(output, cmd)
        # Structure might be nested lists
        if data and len(data) > 0 and len(data[0]) > 0 and data[0][0]:
             return data[0][0]
    return None

def get_aws_iam_role_policy_details(role_name, profile=None):
    """ Fetches attached and inline policies for an IAM role using the specified profile. """
    policies = {'Attached': [], 'Inline': {}}
    # Get attached policies
    cmd_attached = f"aws iam list-attached-role-policies --role-name {role_name} --output json"
    # Pass profile to run_cmd
    output_attached = run_cmd(cmd_attached, profile=profile, suppress_error=True)
    data_attached = parse_json(output_attached, cmd_attached)
    if data_attached and 'AttachedPolicies' in data_attached:
        for policy in data_attached['AttachedPolicies']:
             policies['Attached'].append(policy['PolicyArn'])
             # Potentially fetch policy document details if needed (more calls)

    # Get inline policies (names only first)
    cmd_inline_names = f"aws iam list-role-policies --role-name {role_name} --output json"
    # Pass profile to run_cmd
    output_inline_names = run_cmd(cmd_inline_names, profile=profile, suppress_error=True)
    data_inline_names = parse_json(output_inline_names, cmd_inline_names)
    if data_inline_names and 'PolicyNames' in data_inline_names:
        for policy_name in data_inline_names['PolicyNames']:
            cmd_inline_policy = f"aws iam get-role-policy --role-name {role_name} --policy-name {policy_name} --output json"
            # Pass profile to run_cmd
            output_inline_policy = run_cmd(cmd_inline_policy, profile=profile, suppress_error=True)
            data_inline_policy = parse_json(output_inline_policy, cmd_inline_policy)
            if data_inline_policy and 'PolicyDocument' in data_inline_policy:
                 # Decode URL-encoded policy document if necessary (it often is)
                 import urllib.parse
                 policies['Inline'][policy_name] = json.loads(urllib.parse.unquote(data_inline_policy['PolicyDocument']))

    return policies


# --- Kubernetes Analysis Functions ---
# (No changes needed within the analysis functions themselves, they receive data)
# --- analyze_namespaces ---
def analyze_namespaces(all_findings, namespaces):
    logging.info("Analyzing Namespaces...")
    # Check for Pod Security Admission labels (for K8s 1.23+)
    psa_modes = ['enforce', 'audit', 'warn']
    psa_levels = ['privileged', 'baseline', 'restricted']
    expected_level = 'restricted' # Or baseline, depending on policy

    for ns in namespaces:
        metadata = ns.get('metadata', {})
        ns_name = metadata.get('name')
        labels = metadata.get('labels', {})

        if ns_name in ['kube-system', 'kube-public', 'kube-node-lease']:
            continue # Skip system namespaces for some checks

        # PSA Checks
        psa_enforce_label = labels.get('pod-security.kubernetes.io/enforce')
        if not psa_enforce_label:
             add_finding(all_findings, SEVERITY_MEDIUM, "PSA Label Missing",
                        f"Namespace '{ns_name}' lacks the 'pod-security.kubernetes.io/enforce' label.",
                        f"Apply Pod Security Admission labels to namespaces, enforcing at least the '{expected_level}' standard.",
                        "CIS 1.5.1 / K8s Docs", ns_name, ns_name, "Namespace")
        elif psa_enforce_label not in ['baseline', 'restricted']:
             add_finding(all_findings, SEVERITY_MEDIUM, "PSA Label Too Permissive",
                        f"Namespace '{ns_name}' has PSA enforce level '{psa_enforce_label}'. Expected '{expected_level}' or 'baseline'.",
                        f"Ensure PSA enforce level is set to 'baseline' or preferably 'restricted'.",
                        "CIS 1.5.1 / K8s Docs", ns_name, ns_name, "Namespace")

# --- analyze_pods ---
def analyze_pods(all_findings, pods):
    logging.info("Analyzing Pods...")
    sensitive_hostpaths = ['/', '/etc', '/var', '/usr', '/proc', '/root', '/var/run/docker.sock']

    for pod in pods:
        metadata = pod.get('metadata', {})
        spec = pod.get('spec', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        annotations = metadata.get('annotations', {})

        # Check for IAM Role Annotations (IRSA) - Already present, enhancing details
        iam_role_arn = annotations.get('eks.amazonaws.com/role-arn')
        if iam_role_arn:
            # Basic check for keywords, a deeper IAM policy analysis would be better via AWS checks
            if "admin" in iam_role_arn.lower() or "*" in iam_role_arn: # Very basic check
                add_finding(all_findings, SEVERITY_HIGH, "Pod IRSA Role Potentially Overly Permissive",
                            f"Pod '{name}' uses IAM role '{iam_role_arn}' which might have excessive permissions (contains 'admin' or '*').",
                            "Review and apply least privilege to the IAM role associated via IRSA.",
                            "CIS 5.1.5", ns, name, "Pod")
            # Add informational finding for tracking IRSA usage
            add_finding(all_findings, SEVERITY_INFO, "Pod Using IRSA",
                         f"Pod '{name}' uses IAM role via IRSA: {iam_role_arn}",
                         "Ensure the associated IAM role follows the principle of least privilege.",
                         "AWS Best Practice", ns, name, "Pod")

        # Host Network
        if spec.get('hostNetwork', False):
            add_finding(all_findings, SEVERITY_HIGH, "Pod Using Host Network",
                        f"Pod '{name}' is configured with hostNetwork: true.",
                        "Avoid using hostNetwork. If required, isolate the node.",
                        "CIS 5.2.4", ns, name, "Pod") # Updated CIS ref

        # Host PID/IPC
        if spec.get('hostPID', False):
            add_finding(all_findings, SEVERITY_MEDIUM, "Pod Using Host PID Namespace",
                        f"Pod '{name}' is configured with hostPID: true.",
                        "Avoid using hostPID unless essential.",
                        "CIS 5.2.3", ns, name, "Pod")
        if spec.get('hostIPC', False):
             add_finding(all_findings, SEVERITY_MEDIUM, "Pod Using Host IPC Namespace",
                        f"Pod '{name}' is configured with hostIPC: true.",
                        "Avoid using hostIPC unless essential.",
                        "CIS 5.2.2", ns, name, "Pod")


        # HostPath Volumes
        if spec.get('volumes'):
            for volume in spec.get('volumes', []):
                host_path = volume.get('hostPath')
                if host_path:
                    path = host_path.get('path', '')
                    severity = SEVERITY_MEDIUM
                    details = f"Pod '{name}' uses hostPath volume: '{path}'."
                    if path in sensitive_hostpaths or path.startswith('/var/run'): # Simple check for sensitive paths
                         severity = SEVERITY_HIGH
                         details = f"Pod '{name}' uses sensitive hostPath volume: '{path}'."

                    add_finding(all_findings, severity, "Pod Using HostPath Volume",
                                details,
                                "Avoid hostPath volumes. If necessary, use readOnly mounts and specific paths. Consider alternatives like PVs.",
                                "CIS 5.2.1", ns, name, "Pod") # Updated CIS Ref


        # Check containers within the pod
        containers = spec.get('containers', []) + spec.get('initContainers', []) # Check both
        for container in containers:
            c_name = container.get('name')
            full_name = f"{name}/{c_name}" # Pod/Container

            # Privileged Container
            security_context = container.get('securityContext', {}) # Check container SC first
            if not security_context:
                 security_context = spec.get('securityContext', {}) # Fallback to pod SC

            if security_context.get('privileged', False):
                add_finding(all_findings, SEVERITY_CRITICAL, "Privileged Container",
                            f"Container '{c_name}' in pod '{name}' is running in privileged mode.",
                            "Do not run privileged containers. Refactor the application if possible.",
                            "CIS 5.2.5", ns, full_name, "Container") # Updated CIS Ref

            # Run as Root User
            # Check pod-level first, then container-level (container overrides pod)
            pod_sc = spec.get('securityContext', {})
            container_sc = container.get('securityContext', {})

            run_as_non_root = container_sc.get('runAsNonRoot') # Container specific takes precedence
            if run_as_non_root is None: # If not set on container, check pod
                run_as_non_root = pod_sc.get('runAsNonRoot')

            # If explicitly false or not set at all (defaults to allowing root)
            if run_as_non_root is False or run_as_non_root is None :
                 # Check if runAsUser is explicitly 0
                 run_as_user = container_sc.get('runAsUser')
                 if run_as_user is None:
                    run_as_user = pod_sc.get('runAsUser')

                 if run_as_user == 0:
                     add_finding(all_findings, SEVERITY_MEDIUM, "Container Running As Root",
                                f"Container '{c_name}' in pod '{name}' is configured to run as root (runAsUser: 0).",
                                "Configure container securityContext with runAsNonRoot: true and specify a runAsUser > 0.",
                                "CIS 5.2.6", ns, full_name, "Container")
                 elif run_as_non_root is False:
                      add_finding(all_findings, SEVERITY_MEDIUM, "Container Allowed to Run As Root",
                                f"Container '{c_name}' in pod '{name}' is explicitly allowed to run as root (runAsNonRoot: false).",
                                "Set securityContext.runAsNonRoot: true.",
                                "CIS 5.2.6", ns, full_name, "Container")
                 # If runAsNonRoot is None and runAsUser is not 0 and not None, it's likely okay, but explicit is better.
                 # If both runAsNonRoot and runAsUser are None, it defaults to allowing root, potentially running as root depending on the image.
                 elif run_as_non_root is None and run_as_user is None:
                      add_finding(all_findings, SEVERITY_LOW, "Container May Run As Root",
                                f"Container '{c_name}' in pod '{name}' has no runAsNonRoot or runAsUser specified (default allows root).",
                                "Explicitly set securityContext.runAsNonRoot: true and specify a runAsUser > 0.",
                                "CIS 5.2.6", ns, full_name, "Container")


            # Missing Resource Limits
            resources = container.get('resources', {})
            limits = resources.get('limits')
            if not limits or not limits.get('cpu') or not limits.get('memory'):
                add_finding(all_findings, SEVERITY_LOW, "Container Missing Resource Limits",
                            f"Container '{c_name}' in pod '{name}' lacks CPU and/or memory limits.",
                            "Define CPU and memory limits for all containers.",
                            "CIS 5.5.1", ns, full_name, "Container") # Updated CIS Ref

            # AllowPrivilegeEscalation
            if security_context.get('allowPrivilegeEscalation', True): # Defaults to true
                add_finding(all_findings, SEVERITY_MEDIUM, "Container Allows Privilege Escalation",
                            f"Container '{c_name}' in pod '{name}' allows privilege escalation.",
                            "Set securityContext.allowPrivilegeEscalation: false.",
                            "CIS 5.2.8", ns, full_name, "Container")

            # ReadOnly Root Filesystem
            if not security_context.get('readOnlyRootFilesystem', False):
                 add_finding(all_findings, SEVERITY_LOW, "Container Root Filesystem Writable",
                             f"Container '{c_name}' in pod '{name}' does not have a read-only root filesystem.",
                             "Set securityContext.readOnlyRootFilesystem: true and use volumeMounts for writable directories.",
                             "CIS 5.2.7", ns, full_name, "Container")


            # Image Checks
            image = container.get('image', '')
            if ':' not in image or ':latest' in image:
                 add_finding(all_findings, SEVERITY_LOW, "Image Uses Latest Tag",
                             f"Container '{c_name}' in pod '{name}' uses image '{image}' potentially with 'latest' tag or no tag.",
                             "Use specific image tags instead of 'latest'.",
                             "Best Practice", ns, full_name, "Container")
            # Basic check for known public registries (can be expanded)
            if not any(reg in image for reg in ['amazonaws.com', 'docker.io', 'gcr.io', 'quay.io', 'ghcr.io']):
                 # This is a very rough check, might need adjustment based on approved internal registries
                 add_finding(all_findings, SEVERITY_LOW, "Image From Potentially Untrusted Registry",
                             f"Container '{c_name}' in pod '{name}' uses image '{image}' from a potentially non-standard registry.",
                             "Ensure images are pulled from approved, trusted registries.",
                             "Best Practice", ns, full_name, "Container")


        # Service Account Usage
        sa_name = spec.get('serviceAccountName', 'default') # Defaults to 'default' if not specified
        automount_token = spec.get('automountServiceAccountToken') # Pod level setting

        if sa_name == 'default':
             # Check if the 'default' SA actually has a token mounted
             # Need to correlate with the SA's automount setting
             # This check is refined in analyze_serviceaccounts
             pass # Covered better below

# --- analyze_serviceaccounts ---
def analyze_serviceaccounts(all_findings, service_accounts):
    logging.info("Analyzing Service Accounts...")
    for sa in service_accounts:
        metadata = sa.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        annotations = metadata.get('annotations', {})

        # Check for IAM Role Annotations (IRSA)
        iam_role_arn = annotations.get('eks.amazonaws.com/role-arn')
        if iam_role_arn:
            if "admin" in iam_role_arn.lower() or "*" in iam_role_arn: # Basic check
                add_finding(all_findings, SEVERITY_HIGH, "Service Account IRSA Role Potentially Overly Permissive",
                            f"ServiceAccount '{name}' uses IAM role '{iam_role_arn}' which might have excessive permissions (contains 'admin' or '*').",
                            "Review and apply least privilege to the IAM role associated via IRSA.",
                            "CIS 5.1.5", ns, name, "ServiceAccount")
            add_finding(all_findings, SEVERITY_INFO, "Service Account Using IRSA",
                         f"ServiceAccount '{name}' uses IAM role via IRSA: {iam_role_arn}",
                         "Ensure the associated IAM role follows the principle of least privilege.",
                         "AWS Best Practice", ns, name, "ServiceAccount")


        # Check automountServiceAccountToken
        automount_token = sa.get('automountServiceAccountToken') # SA level setting
        # Note: Pod spec can override this. This checks the SA default.
        if automount_token is True or automount_token is None: # Default is true
            if name != "default": # Report non-default SAs that automount
                 add_finding(all_findings, SEVERITY_MEDIUM, "Service Account Token Automount Enabled",
                             f"ServiceAccount '{name}' has automountServiceAccountToken enabled (or default). Tokens might be mounted unnecessarily.",
                             "Set automountServiceAccountToken: false on the ServiceAccount unless pods using it specifically need the token.",
                             "CIS 5.1.6", ns, name, "ServiceAccount") # Updated CIS Ref
            else: # Special attention to the 'default' SA
                 add_finding(all_findings, SEVERITY_MEDIUM, "Default Service Account Allows Token Automount",
                             f"The 'default' ServiceAccount in namespace '{ns}' allows token automounting.",
                             "Explicitly set automountServiceAccountToken: false on the 'default' ServiceAccount.",
                             "CIS 5.1.6", ns, name, "ServiceAccount")

# --- analyze_rbac ---
def analyze_rbac(all_findings, roles, role_bindings, cluster_roles, cluster_role_bindings):
    logging.info("Analyzing RBAC (Roles, ClusterRoles, Bindings)...")
    sensitive_verbs = ["*", "create", "update", "patch", "delete", "deletecollection", "impersonate", "bind", "escalate"]
    sensitive_resources = ["*", "secrets", "pods", "pods/exec", "pods/attach", "deployments", "daemonsets", "statefulsets", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "serviceaccounts", "nodes", "certificatesigningrequests"]
    highly_privileged_roles = ["cluster-admin", "admin", "edit"] # Also check for custom roles granting similar permissions

    # Analyze ClusterRoleBindings
    for crb in cluster_role_bindings:
        metadata = crb.get('metadata', {})
        crb_name = metadata.get('name')
        role_ref = crb.get('roleRef', {})
        role_name = role_ref.get('name')
        subjects = crb.get('subjects', [])

        if role_name in highly_privileged_roles:
            for subject in subjects:
                 subject_name = subject.get('name')
                 subject_kind = subject.get('kind')
                 subject_ns = subject.get('namespace', '(cluster)') # SA subjects have ns
                 full_subject_name = f"{subject_kind}:{subject_name}"
                 if subject_kind == "ServiceAccount":
                     full_subject_name = f"{subject_kind}:{subject_ns}/{subject_name}"

                 add_finding(all_findings, SEVERITY_HIGH, "ClusterRoleBinding Grants High Privileges",
                             f"ClusterRoleBinding '{crb_name}' grants highly privileged role '{role_name}' to '{full_subject_name}'.",
                             "Avoid binding cluster-admin or similar roles directly. Use namespace-scoped roles or custom cluster roles with least privilege.",
                             "CIS 5.1.1", '(cluster)', crb_name, "ClusterRoleBinding")

        # Check bindings to sensitive system groups/users
        sensitive_subjects = {
            "ServiceAccount:kube-system/default",
            "Group:system:unauthenticated",
            "Group:system:authenticated",
            # "Group:system:masters" # Usually okay, but context matters
        }
        for subject in subjects:
             subject_name = subject.get('name')
             subject_kind = subject.get('kind')
             subject_ns = subject.get('namespace', '')
             full_subject_name = f"{subject_kind}:{subject_name}"
             if subject_kind == "ServiceAccount" and subject_ns:
                 full_subject_name = f"{subject_kind}:{subject_ns}/{subject_name}"

             if full_subject_name in sensitive_subjects:
                  add_finding(all_findings, SEVERITY_MEDIUM, "ClusterRoleBinding to Sensitive Subject",
                              f"ClusterRoleBinding '{crb_name}' grants role '{role_name}' to potentially sensitive subject '{full_subject_name}'.",
                              "Review bindings to system groups and default service accounts, especially in kube-system.",
                              "CIS 5.1.1 / Best Practice", '(cluster)', crb_name, "ClusterRoleBinding")


    # Analyze RoleBindings (Namespace-level)
    for rb in role_bindings:
        metadata = rb.get('metadata', {})
        rb_name = metadata.get('name')
        ns = metadata.get('namespace')
        role_ref = rb.get('roleRef', {})
        role_kind = role_ref.get('kind')
        role_name = role_ref.get('name')
        subjects = rb.get('subjects', [])

        # Check for bindings granting admin/edit roles within the namespace
        if role_name in ["admin", "edit"]:
             for subject in subjects:
                 subject_name = subject.get('name')
                 subject_kind = subject.get('kind')
                 add_finding(all_findings, SEVERITY_MEDIUM, "RoleBinding Grants High Privileges in Namespace",
                             f"RoleBinding '{rb_name}' in namespace '{ns}' grants '{role_name}' role to {subject_kind} '{subject_name}'.",
                             "Use custom roles with least privilege instead of built-in admin/edit roles where possible.",
                             "CIS 5.1.1", ns, rb_name, "RoleBinding")

        # Check for bindings involving the default service account
        for subject in subjects:
            if subject.get('kind') == "ServiceAccount" and subject.get('name') == "default":
                 add_finding(all_findings, SEVERITY_MEDIUM, "RoleBinding Involves Default Service Account",
                             f"RoleBinding '{rb_name}' in namespace '{ns}' grants role '{role_name}' to the 'default' ServiceAccount.",
                             "Avoid granting permissions to the 'default' service account. Use dedicated service accounts.",
                             "CIS 5.1.3", ns, rb_name, "RoleBinding")

    # Analyze ClusterRoles and Roles for risky permissions
    all_roles = [('ClusterRole', r) for r in cluster_roles] + [('Role', r) for r in roles]
    for role_type, role in all_roles:
        metadata = role.get('metadata', {})
        role_name = metadata.get('name')
        ns = metadata.get('namespace', '(cluster)') # Roles have namespace, ClusterRoles don't
        rules = role.get('rules', [])

        for rule in rules:
            verbs = rule.get('verbs', [])
            resources = rule.get('resources', [])

            has_sensitive_verb = any(v in sensitive_verbs for v in verbs)
            has_sensitive_resource = any(r in sensitive_resources for r in resources)
            has_wildcard_verb = "*" in verbs
            has_wildcard_resource = "*" in resources

            if has_wildcard_verb or has_wildcard_resource or (has_sensitive_verb and has_sensitive_resource):
                severity = SEVERITY_LOW
                if has_wildcard_verb or has_wildcard_resource:
                    severity = SEVERITY_MEDIUM
                if role_name in highly_privileged_roles or role_type == 'ClusterRole':
                     # Already covered by binding checks mostly, but highlight risky definition
                     severity = SEVERITY_MEDIUM if severity == SEVERITY_LOW else severity # Escalate if clusterrole


                details = f"{role_type} '{role_name}' contains potentially risky permissions:"
                if has_wildcard_verb: details += " wildcard verb"
                if has_wildcard_resource: details += " wildcard resource"
                if has_sensitive_verb and has_sensitive_resource: details += f" sensitive verb(s) on sensitive resource(s) ({verbs} on {resources})"

                # Reduce noise for default roles unless really bad like wildcard * *
                is_default_role = role_name.startswith("system:") or role_name in ["cluster-admin", "admin", "edit", "view"]
                if not is_default_role or (has_wildcard_resource and has_wildcard_verb):
                    add_finding(all_findings, severity, "Role Contains Risky Permissions",
                                details,
                                f"Review the permissions granted by {role_type} '{role_name}' and apply least privilege.",
                                "CIS 5.1.2", ns, role_name, role_type)

# --- analyze_network_policies ---
def analyze_network_policies(all_findings, network_policies_by_ns, all_namespaces):
    logging.info("Analyzing Network Policies...")
    namespaces_with_policies = set(network_policies_by_ns.keys())
    all_ns_names = {ns.get('metadata', {}).get('name') for ns in all_namespaces}

    # Check namespaces without any network policies
    for ns_name in all_ns_names:
        if ns_name not in namespaces_with_policies and ns_name not in ['kube-system', 'kube-public', 'kube-node-lease']: # Exclude system ns
            add_finding(all_findings, SEVERITY_MEDIUM, "Namespace Lacks Network Policy",
                        f"Namespace '{ns_name}' has no NetworkPolicy defined, allowing all ingress/egress traffic by default.",
                        "Implement NetworkPolicies to restrict pod-to-pod communication based on the principle of least privilege. Start with a default deny policy.",
                        "CIS 5.3.2", ns_name, ns_name, "Namespace")

    # Analyze existing policies (basic checks)
    for ns, policies in network_policies_by_ns.items():
        has_default_deny = False
        for policy in policies:
             metadata = policy.get('metadata', {})
             policy_name = metadata.get('name')
             spec = policy.get('spec', {})

             # Check for default deny (applies to all pods, denies all ingress/egress)
             pod_selector = spec.get('podSelector')
             if pod_selector is not None and not pod_selector: # Empty podSelector means applies to all pods in ns
                 policy_types = spec.get('policyTypes', ['Ingress']) # Default is Ingress if not specified
                 is_ingress_deny = 'Ingress' in policy_types and 'ingress' not in spec # No ingress rules means deny ingress
                 is_egress_deny = 'Egress' in policy_types and 'egress' not in spec # No egress rules means deny egress

                 if is_ingress_deny and is_egress_deny :
                     has_default_deny = True
                     add_finding(all_findings, SEVERITY_INFO, "Namespace Has Default Deny Network Policy",
                                 f"Namespace '{ns}' appears to have a default deny policy: '{policy_name}'.",
                                 "Verify this policy correctly implements default deny and allows necessary traffic through other policies.",
                                 "Best Practice", ns, policy_name, "NetworkPolicy")
                 elif is_ingress_deny:
                      add_finding(all_findings, SEVERITY_INFO, "Namespace Has Default Ingress Deny Network Policy",
                                  f"Namespace '{ns}' appears to have a default ingress deny policy: '{policy_name}'.",
                                  "Ensure necessary ingress traffic is allowed by other policies.",
                                  "Best Practice", ns, policy_name, "NetworkPolicy")
                 elif is_egress_deny:
                     add_finding(all_findings, SEVERITY_INFO, "Namespace Has Default Egress Deny Network Policy",
                                  f"Namespace '{ns}' appears to have a default egress deny policy: '{policy_name}'.",
                                  "Ensure necessary egress traffic is allowed by other policies.",
                                  "Best Practice", ns, policy_name, "NetworkPolicy")

             # Check for overly broad allow rules (e.g., allowing from any namespace or any pod)
             ingress_rules = spec.get('ingress', [])
             for rule in ingress_rules:
                 from_rules = rule.get('from', [])
                 if not from_rules: # Allows all sources if 'from' is empty or omitted
                      add_finding(all_findings, SEVERITY_LOW, "Network Policy Allows All Ingress Sources",
                                  f"Policy '{policy_name}' in namespace '{ns}' has an ingress rule potentially allowing traffic from all sources.",
                                  "Specify podSelectors or namespaceSelectors in ingress rules to restrict allowed sources.",
                                  "CIS 5.3.1", ns, policy_name, "NetworkPolicy")
                 for from_rule in from_rules:
                     # {} in podSelector or namespaceSelector means allow all pods/namespaces
                     if from_rule.get('podSelector') == {}:
                          add_finding(all_findings, SEVERITY_LOW, "Network Policy Allows Ingress From All Pods",
                                      f"Policy '{policy_name}' in namespace '{ns}' has an ingress rule allowing traffic from all pods via empty podSelector.",
                                      "Specify labels in podSelectors to restrict allowed source pods.",
                                      "CIS 5.3.1", ns, policy_name, "NetworkPolicy")
                     if from_rule.get('namespaceSelector') == {}:
                           add_finding(all_findings, SEVERITY_LOW, "Network Policy Allows Ingress From All Namespaces",
                                       f"Policy '{policy_name}' in namespace '{ns}' has an ingress rule allowing traffic from all namespaces via empty namespaceSelector.",
                                       "Specify labels in namespaceSelectors to restrict allowed source namespaces.",
                                       "CIS 5.3.1", ns, policy_name, "NetworkPolicy")
                     if 'ipBlock' in from_rule:
                         cidr = from_rule['ipBlock'].get('cidr')
                         if cidr == '0.0.0.0/0':
                              add_finding(all_findings, SEVERITY_MEDIUM, "Network Policy Allows Ingress From Any IP",
                                          f"Policy '{policy_name}' in namespace '{ns}' has an ingress rule allowing traffic from any IP (0.0.0.0/0).",
                                          "Restrict ipBlock CIDRs to only necessary source IP ranges.",
                                          "CIS 5.3.1", ns, policy_name, "NetworkPolicy")

# --- analyze_secrets_configmaps ---
def analyze_secrets_configmaps(all_findings, secrets, configmaps):
    logging.info("Analyzing Secrets and ConfigMaps (Basic Checks)...")
    # Warning: Cannot read secret data with read-only access. Checks are basic.
    potentially_sensitive_key_patterns = ['password', 'secret', 'token', 'key', 'passwd', 'pwd', 'auth', 'credential']

    for secret in secrets:
        metadata = secret.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        secret_type = secret.get('type', 'Opaque')

        # Check common secret types that might contain credentials
        if secret_type in ['kubernetes.io/basic-auth', 'kubernetes.io/ssh-auth', 'kubernetes.io/dockerconfigjson', 'kubernetes.io/tls']:
             add_finding(all_findings, SEVERITY_INFO, "Potentially Sensitive Secret Type",
                         f"Secret '{name}' has type '{secret_type}', often used for credentials or sensitive data.",
                         "Ensure access to this secret is tightly controlled via RBAC. Ensure application retrieves specific keys, not the entire secret.",
                         "Best Practice", ns, name, "Secret")

    for cm in configmaps:
        metadata = cm.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        data = cm.get('data', {})

        for key in data.keys():
            if any(pattern in key.lower() for pattern in potentially_sensitive_key_patterns):
                 add_finding(all_findings, SEVERITY_MEDIUM, "Potential Sensitive Data in ConfigMap",
                             f"ConfigMap '{name}' contains a key '{key}' which might indicate sensitive data stored insecurely.",
                             "Do not store secrets or sensitive credentials in ConfigMaps. Use Kubernetes Secrets instead.",
                             "CIS 5.4.1", ns, name, "ConfigMap")

# --- AWS EKS Analysis Functions ---

def analyze_eks_cluster_config(all_findings, cluster_info, cluster_name, region):
    logging.info("Analyzing EKS Cluster Configuration...")
    if not cluster_info:
        logging.error("Skipping EKS cluster analysis due to previous fetch error.")
        return

    cluster_arn = cluster_info.get('arn')
    config = cluster_info.get('resourcesVpcConfig', {})
    logging_config = cluster_info.get('logging', {}).get('clusterLogging', [])
    version = cluster_info.get('version')
    platform_version = cluster_info.get('platformVersion')

    add_finding(all_findings, SEVERITY_INFO, "EKS Cluster Version",
                f"Cluster '{cluster_name}' is running Kubernetes version '{version}' and EKS platform version '{platform_version}'.",
                "Ensure the Kubernetes version is supported and patched. Regularly review EKS platform version updates.",
                "AWS Best Practice", '(cluster)', cluster_name, "EKS Cluster")


    # Endpoint Access
    public_access = config.get('endpointPublicAccess', False)
    private_access = config.get('endpointPrivateAccess', False)
    public_cidrs = config.get('publicAccessCidrs', [])

    if public_access:
        if not public_cidrs or "0.0.0.0/0" in public_cidrs:
             add_finding(all_findings, SEVERITY_HIGH, "EKS Public API Endpoint Open to Internet",
                         f"EKS cluster '{cluster_name}' API endpoint is publicly accessible from all IPs (0.0.0.0/0).",
                         "Restrict public access CIDRs to trusted networks or disable public access if private access is enabled and sufficient.",
                         "CIS 1.1.1", '(cluster)', cluster_name, "EKS Cluster")
        else:
             add_finding(all_findings, SEVERITY_LOW, "EKS Public API Endpoint Access Enabled",
                         f"EKS cluster '{cluster_name}' API endpoint is publicly accessible from specific CIDRs: {public_cidrs}.",
                         "Ensure the allowed CIDRs are necessary and restricted to the minimum required ranges. Prefer private access where possible.",
                         "CIS 1.1.1", '(cluster)', cluster_name, "EKS Cluster")

    if not private_access and not public_access:
        # This state shouldn't normally happen via API/Console, but check anyway
        add_finding(all_findings, SEVERITY_HIGH, "EKS API Endpoint Access Disabled",
                    f"EKS cluster '{cluster_name}' has both public and private API endpoint access disabled.",
                    "Review cluster configuration. At least one access method (preferably private) should be enabled.",
                    "AWS Error", '(cluster)', cluster_name, "EKS Cluster")
    elif not private_access and public_access:
         add_finding(all_findings, SEVERITY_MEDIUM, "EKS Private API Endpoint Access Disabled",
                     f"EKS cluster '{cluster_name}' does not have private API endpoint access enabled. Access relies on public endpoint.",
                     "Enable private endpoint access for improved security and network isolation.",
                     "AWS Best Practice", '(cluster)', cluster_name, "EKS Cluster")


    # Control Plane Logging
    required_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
    enabled_logs = [item['types'] for item in logging_config if item.get('enabled')]
    # Flatten the list of lists
    enabled_logs_flat = [log_type for sublist in enabled_logs for log_type in sublist]

    missing_logs = [log for log in required_logs if log not in enabled_logs_flat]
    if missing_logs:
        add_finding(all_findings, SEVERITY_MEDIUM, "EKS Control Plane Logging Disabled",
                    f"EKS cluster '{cluster_name}' is missing control plane log types: {', '.join(missing_logs)}.",
                    f"Enable all control plane log types ({', '.join(required_logs)}) for auditing and troubleshooting.",
                    "CIS 1.1.2", '(cluster)', cluster_name, "EKS Cluster")
    else:
         add_finding(all_findings, SEVERITY_INFO, "EKS Control Plane Logging Enabled",
                     f"EKS cluster '{cluster_name}' has all recommended control plane log types enabled.",
                     "Ensure logs are being ingested and monitored in CloudWatch Logs or another SIEM.",
                     "CIS 1.1.2", '(cluster)', cluster_name, "EKS Cluster")

    # Secrets Encryption
    encryption_config = cluster_info.get('encryptionConfig', [])
    if not encryption_config or not any(cfg.get('provider', {}).get('keyArn') for cfg in encryption_config):
         add_finding(all_findings, SEVERITY_HIGH, "EKS Secrets Encryption Not Enabled",
                     f"EKS cluster '{cluster_name}' does not have envelope encryption for Kubernetes secrets enabled.",
                     "Enable envelope encryption using a KMS key to protect Kubernetes secrets at rest.",
                     "CIS 1.1.3", '(cluster)', cluster_name, "EKS Cluster")
    else:
         # Check if 'secrets' resource is included
         secrets_encrypted = False
         for cfg in encryption_config:
             if 'secrets' in cfg.get('resources', []):
                 secrets_encrypted = True
                 key_arn = cfg.get('provider', {}).get('keyArn')
                 add_finding(all_findings, SEVERITY_INFO, "EKS Secrets Encryption Enabled",
                             f"EKS cluster '{cluster_name}' has envelope encryption enabled for secrets using KMS key: {key_arn}.",
                             "Ensure the KMS key policy is appropriately restricted.",
                             "CIS 1.1.3", '(cluster)', cluster_name, "EKS Cluster")
                 break
         if not secrets_encrypted:
              add_finding(all_findings, SEVERITY_HIGH, "EKS Secrets Resource Not Included in Encryption Config",
                         f"EKS cluster '{cluster_name}' has encryption configured, but the 'secrets' resource is not explicitly included.",
                         "Ensure the 'secrets' resource is included in the encryptionConfig.",
                         "CIS 1.1.3", '(cluster)', cluster_name, "EKS Cluster")

     # Cluster IAM Role Analysis (Basic - relies on user having IAM permissions)
    cluster_role_arn = cluster_info.get('roleArn')
    if cluster_role_arn:
        role_name = cluster_role_arn.split('/')[-1]
        add_finding(all_findings, SEVERITY_INFO, "EKS Cluster IAM Role",
                     f"EKS cluster '{cluster_name}' uses IAM role: {role_name} ({cluster_role_arn}).",
                     "Review the policies attached to this role (e.g., AmazonEKSClusterPolicy) to ensure they are not overly permissive.",
                     "AWS Best Practice", '(cluster)', cluster_name, "EKS Cluster IAM Role")
        # Deeper analysis requires get_aws_iam_role_policy_details(role_name) called elsewhere


def analyze_eks_nodegroups(all_findings, nodegroups, cluster_name, region):
    logging.info("Analyzing EKS Nodegroups...")
    if not nodegroups:
        logging.info("No managed nodegroups found to analyze.")
        return

    for ng in nodegroups:
        ng_name = ng.get('nodegroupName')
        ng_arn = ng.get('nodegroupArn')
        version_info = ng.get('releaseVersion') # AMI release version
        ami_type = ng.get('amiType')
        instance_types = ng.get('instanceTypes')
        node_role_arn = ng.get('nodeRole')
        resources = ng.get('resources', {})
        remote_access = ng.get('remoteAccess', {})
        ec2_ssh_key = remote_access.get('ec2SshKey')
        source_sgs = remote_access.get('sourceSecurityGroups', [])
        launch_template = ng.get('launchTemplate', {}) # Can override many settings

        asset_name = f"{cluster_name}/{ng_name}"
        asset_type = "EKS Nodegroup"

        add_finding(all_findings, SEVERITY_INFO, "Nodegroup Configuration",
                    f"Nodegroup '{ng_name}': AMI Type '{ami_type}', Version '{version_info}', Instances '{','.join(instance_types)}', Role '{node_role_arn.split('/')[-1]}'.",
                    "Review nodegroup configuration settings. Ensure AMI type and version are current.",
                    "AWS Best Practice", '(cluster)', asset_name, asset_type)


        # Check for Remote SSH Access
        if ec2_ssh_key:
             if not source_sgs:
                 add_finding(all_findings, SEVERITY_HIGH, "Nodegroup SSH Access Enabled Without Source Restriction",
                             f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}' but no source security groups defined, potentially allowing access from anywhere.",
                             "Define source security groups for SSH access or disable SSH access if not required.",
                             "CIS 4.1.1", '(cluster)', asset_name, asset_type)
             else:
                 add_finding(all_findings, SEVERITY_MEDIUM, "Nodegroup SSH Access Enabled",
                             f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}' restricted to SGs: {source_sgs}.",
                             "Ensure SSH access is necessary and the source security groups are appropriately restricted. Disable if not needed.",
                             "CIS 4.1.1", '(cluster)', asset_name, asset_type)
        else:
             add_finding(all_findings, SEVERITY_INFO, "Nodegroup SSH Access Disabled",
                         f"Nodegroup '{ng_name}' does not have EC2 SSH key configured.",
                         "SSH access to nodes is disabled via the nodegroup configuration (verify launch template overrides).",
                         "CIS 4.1.1", '(cluster)', asset_name, asset_type)

        # Check Node IAM Role (Basic - Deeper analysis requires IAM permissions)
        if node_role_arn:
             role_name = node_role_arn.split('/')[-1]
             add_finding(all_findings, SEVERITY_INFO, "Nodegroup IAM Role",
                         f"Nodegroup '{ng_name}' uses Node IAM role: {role_name} ({node_role_arn}).",
                         "Review policies attached (e.g., AmazonEKSWorkerNodePolicy, AmazonEC2ContainerRegistryReadOnly, AmazonEKS_CNI_Policy). Ensure no excessive permissions.",
                         "AWS Best Practice", '(cluster)', asset_name, f"{asset_type} IAM Role")
             # TODO: Call get_aws_iam_role_policy_details(role_name, profile=profile) if IAM perms exist
             # policies = get_aws_iam_role_policy_details(role_name, profile=args.profile) # Need profile here
             # Analyze policies for broad permissions like ec2:*, s3:*, iam:*, *:*)

        # IMDSv2 Check (Requires EC2 permissions, often not available)
        # This part is tricky as it needs an instance ID from the nodegroup,
        # and permissions for ec2:DescribeInstances. Attempt if possible.
        # instance_ids = resources.get('autoScalingGroups', [{}])[0].get('name') # ASG name, not instances
        # Need to list instances in the ASG or use EC2 tags... complex for read-only scan.
        # Placeholder - A manual check or different tool might be needed here.
        add_finding(all_findings, SEVERITY_INFO, "IMDSv2 Check Needed",
                     f"Nodegroup '{ng_name}': Check associated EC2 instances or Launch Template.",
                     "Verify if IMDSv2 is enforced (MetadataHttpTokens=required) on EC2 instances to mitigate SSRF risks. This requires ec2:DescribeInstances or checking the Launch Template.",
                     "CIS 4.1.3", '(cluster)', asset_name, asset_type)


# --- Reporting ---

def export_findings_to_csv(findings, filename="eks_findings_plextrac.csv"):
    """Exports findings to a CSV file formatted for Plextrac import."""
    if not findings:
        logging.info("No findings to export.")
        return

    # More comprehensive Plextrac fields
    fieldnames = [
        "Finding Name", # (Title) -> finding['type']
        "Severity", # finding['severity']
        "Status", # Default 'Open'
        "Description", # finding['details']
        "Recommendation", # finding['recommendation']
        "Vulnerability References", # finding['reference']
        "Affected Components", # -> asset identifier: namespace/name or ARN
        "Tags", # Static + dynamic (e.g., resource type)
        # Add more Plextrac custom fields if needed
        # "CVSS", "CVE", "NIST CSF", "OWASP", etc.
    ]

    logging.info(f"Exporting {len(findings)} findings to {filename}...")
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore') # Ignore extra keys in finding dict
            writer.writeheader()
            for finding in findings:
                # Construct Affected Component string
                affected_component = f"{finding['namespace']}/{finding['name']}"
                if finding['namespace'] == '(cluster)':
                     affected_component = finding['name'] # For cluster-level resources

                writer.writerow({
                    "Finding Name": finding['type'],
                    "Severity": finding['severity'],
                    "Status": "Open", # Default status
                    "Description": finding['details'],
                    "Recommendation": finding['recommendation'],
                    "Vulnerability References": finding['reference'],
                    "Affected Components": affected_component,
                    "Tags": f"EKS,Kubernetes,Security,{finding['asset_type']}", # Add asset type as tag
                })
        logging.info(f"Successfully exported findings to {filename}")
    except IOError as e:
        logging.error(f"Failed to write CSV file {filename}: {e}")
    except Exception as e:
         logging.error(f"An unexpected error occurred during CSV export: {e}")


# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="AWS EKS Security Scanner (Read-Only)")
    parser.add_argument("--cluster-name", required=True, help="Name of the EKS cluster")
    parser.add_argument("--region", required=True, help="AWS region of the EKS cluster")
    # --- NEW ARGUMENTS ---
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--context", help="kubectl context to use")
    # --- END NEW ARGUMENTS ---
    parser.add_argument("-o", "--output-file", default="eks_findings_plextrac.csv", help="Output CSV file name")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    # Add namespace filtering if needed:
    # parser.add_argument("--namespaces", nargs='+', help="Specific namespaces to scan (default: all)")
    # parser.add_argument("--exclude-namespaces", nargs='+', default=['kube-system', 'kube-public', 'kube-node-lease'], help="Namespaces to exclude")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    all_findings = []
    start_time = datetime.now()
    logging.info(f"Starting AWS EKS Security Scanner for cluster '{args.cluster_name}' in region '{args.region}'...")
    logging.info(f"Using AWS Profile: '{args.profile or 'default'}' | Using kubectl Context: '{args.context or 'default'}'") # Log which ones are used
    logging.info("NOTE: This script uses read-only kubectl and aws cli commands.")

    # Basic check for dependencies (pass profile/context here too)
    logging.info("Checking dependencies...")
    if run_cmd("kubectl version --client --short", context=args.context, check_rc=False, suppress_error=True) is None:
        logging.error(f"kubectl command not found or not working (context: {args.context or 'default'}). Please install and configure kubectl.")
        sys.exit(1)
    if run_cmd("aws sts get-caller-identity", profile=args.profile, check_rc=False, suppress_error=True) is None:
         logging.error(f"AWS CLI command not found or not working/authenticated (profile: {args.profile or 'default'}). Please install/configure AWS CLI.")
         sys.exit(1)
    logging.info("Dependencies check passed.")


    # 1. Fetch AWS EKS Data (pass profile)
    logging.info("--- Fetching AWS EKS Data ---")
    eks_cluster_info = get_aws_eks_cluster_info(args.cluster_name, args.region, profile=args.profile)
    eks_nodegroups = get_aws_eks_nodegroups(args.cluster_name, args.region, profile=args.profile)
    # Add fetching other AWS resources if needed (pass profile)

    # 2. Fetch Kubernetes Resources (Efficiently) (pass context)
    logging.info("--- Fetching Kubernetes Resources ---")
    namespaces = get_k8s_resources("namespaces", context=args.context)
    pods = get_k8s_resources("pods", context=args.context, use_all_namespaces=True)
    service_accounts = get_k8s_resources("serviceaccounts", context=args.context, use_all_namespaces=True)
    roles = get_k8s_resources("roles", context=args.context, use_all_namespaces=True)
    role_bindings = get_k8s_resources("rolebindings", context=args.context, use_all_namespaces=True)
    cluster_roles = get_k8s_resources("clusterroles", context=args.context) # No namespace
    cluster_role_bindings = get_k8s_resources("clusterrolebindings", context=args.context) # No namespace
    network_policies_all = get_k8s_resources("networkpolicy", context=args.context, use_all_namespaces=True)
    secrets = get_k8s_resources("secrets", context=args.context, use_all_namespaces=True)
    configmaps = get_k8s_resources("configmaps", context=args.context, use_all_namespaces=True)
    # Add DaemonSets, StatefulSets, Ingress, etc. as needed (pass context)
    # daemonsets = get_k8s_resources("daemonsets", context=args.context, use_all_namespaces=True)
    # statefulsets = get_k8s_resources("statefulsets", context=args.context, use_all_namespaces=True)

    # Pre-process network policies by namespace for easier lookup
    network_policies_by_ns = {}
    for np in network_policies_all:
        ns = np.get('metadata', {}).get('namespace')
        if ns:
            if ns not in network_policies_by_ns:
                network_policies_by_ns[ns] = []
            network_policies_by_ns[ns].append(np)

    # 3. Run Analysis Functions (no changes needed here, they operate on fetched data)
    logging.info("--- Analyzing Resources ---")
    analyze_eks_cluster_config(all_findings, eks_cluster_info, args.cluster_name, args.region)
    # Pass profile down if needed for deeper checks like IAM role policy analysis within analyze_eks_nodegroups
    analyze_eks_nodegroups(all_findings, eks_nodegroups, args.cluster_name, args.region)

    analyze_namespaces(all_findings, namespaces)
    analyze_pods(all_findings, pods)
    analyze_serviceaccounts(all_findings, service_accounts)
    analyze_rbac(all_findings, roles, role_bindings, cluster_roles, cluster_role_bindings)
    analyze_network_policies(all_findings, network_policies_by_ns, namespaces)
    analyze_secrets_configmaps(all_findings, secrets, configmaps)
    # Add calls to analyze other fetched resources

    # 4. Report Findings
    logging.info("--- Scan Complete ---")
    end_time = datetime.now()
    logging.info(f"Scan duration: {end_time - start_time}")

    if all_findings:
        logging.info(f"Found {len(all_findings)} potential issues.")
        # Optional: Print summary to console
        print("\n--- Findings Summary ---")
        severity_counts = {}
        for f in all_findings:
            sev = f['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
             if sev in severity_counts:
                 print(f"- {sev}: {severity_counts[sev]}")

        export_findings_to_csv(all_findings, args.output_file)
    else:
        logging.info("No specific security issues found based on the current checks.")

if __name__ == "__main__":
    # Initial argument parsing needed before dependency checks to get profile/context
    # Using a basic pre-parser, or just parse fully and use args in dependency checks
    # Full parse is easier here:
    parser = argparse.ArgumentParser(add_help=False) # Temp parser to get profile/context
    parser.add_argument("--profile", help=argparse.SUPPRESS)
    parser.add_argument("--context", help=argparse.SUPPRESS)
    pre_args, _ = parser.parse_known_args()

    # Basic check for dependencies using potentially provided profile/context
    # Using suppress_error=True to avoid exiting if the *check* command fails, main parser will handle missing req args later
    if run_cmd("kubectl version --client --short", context=pre_args.context, check_rc=False, suppress_error=True) is None:
        # We only log error here, main() will exit properly if called later without tools
        logging.warning(f"kubectl command check failed (context: {pre_args.context or 'default'}). Ensure it's installed and configured.")
        # sys.exit(1) # Don't exit yet, let main handle argument requirements first

    if run_cmd("aws sts get-caller-identity", profile=pre_args.profile, check_rc=False, suppress_error=True) is None:
        logging.warning(f"AWS CLI command check failed (profile: {pre_args.profile or 'default'}). Ensure it's installed and configured.")
        # sys.exit(1) # Don't exit yet

    # Run the main function which includes full parsing and execution
    main()
