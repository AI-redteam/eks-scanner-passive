#!/usr/bin/env python3

import subprocess
import json
import csv
import argparse
import logging
import sys
from datetime import datetime
import urllib.parse # Needed for decoding IAM policy docs

asci_1 = '''
 ______       ___   ___      ______                     ______       ______       ______       __  __       _________  
/_____/\     /___/\/__/\    /_____/\                   /_____/\     /_____/\     /_____/\     /_/\/_/\     /________/\ 
\::::_\/_    \::.\ \\ \ \   \::::_\/_       _______    \::::_\/_    \:::__\/     \:::_ \ \    \:\ \:\ \    \__.::.__\/ 
 \:\/___/\    \:: \/_) \ \   \:\/___/\     /______/\    \:\/___/\    \:\ \  __    \:\ \ \ \    \:\ \:\ \      \::\ \   
  \::___\/_    \:. __  ( (    \_::._\:\    \__::::\/     \_::._\:\    \:\ \/_/\    \:\ \ \ \    \:\ \:\ \      \::\ \  
   \:\____/\    \: \ )  \ \     /____\:\                   /____\:\    \:\_\ \ \    \:\_\ \ \    \:\_\:\ \      \::\ \ 
    \_____\/     \__\/\__\/     \_____\/                   \_____\/     \_____\/     \_____\/     \_____\/       \__\/ 
                                                                                                                       
'''

print(asci_1)

# --- Configuration ---
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def run_cmd(cmd, profile=None, context=None, check_rc=True, suppress_error=False):
    """
    Runs a shell command, optionally injecting AWS profile and kubectl context.
    Returns its stdout.
    """
    if cmd.strip().startswith("kubectl ") and context:
        cmd = f"kubectl --context {context} {cmd[len('kubectl '):]}"
    elif cmd.strip().startswith("aws ") and profile:
        cmd = f"aws --profile {profile} {cmd[len('aws '):]}"

    logging.debug(f"Running command: {cmd}")
    try:
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
        return None
    except Exception as e:
        logging.error(f"Unexpected error running command '{cmd}': {e}")
        return None


def parse_json(json_string, cmd_for_error=""):
    """Safely parses a JSON string."""
    if not json_string:
        return None
    try:
        return json.loads(json_string)
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON output from command '{cmd_for_error}': {e}")
        logging.debug(f"Invalid JSON string: {json_string[:500]}...")
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
    # Split resource types if multiple are requested (e.g., "resourcequota,limitrange")
    resources_to_get = resource_type.split(',')
    all_items = []
    for res_type in resources_to_get:
        res_type = res_type.strip()
        if not res_type: continue
        cmd = f"kubectl get {res_type} {namespace_flag} {all_namespaces_flag} -o json"
        output = run_cmd(cmd, context=context, suppress_error=True)
        if output is None:
            logging.warning(f"Could not retrieve {res_type}s (context: {context or 'default'}). Skipping checks for this type.")
            continue # Continue to next resource type if one fails
        data = parse_json(output, cmd)
        if data and 'items' in data:
            all_items.extend(data['items'])
        elif output.strip() != "" and "No resources found" not in output:
            # Handle cases where 'items' might be missing but there was output suggesting an issue
             logging.warning(f"Received unexpected non-empty, non-item output for {res_type} (context: {context or 'default'}). Output: {output[:200]}...")


    # Return a dictionary-like structure if multiple types were requested, keyed by kind
    # Or just a list if only one type was requested
    if len(resources_to_get) > 1:
        resource_map = {}
        for item in all_items:
            kind = item.get('kind')
            if kind:
                if kind not in resource_map:
                    resource_map[kind] = []
                resource_map[kind].append(item)
        return resource_map
    else:
         return all_items # Should be a list from the single type fetch


# --- AWS Resource Fetching Functions ---
# (No changes needed in these specific functions for this request)
def get_aws_eks_cluster_info(cluster_name, region, profile=None):
    """Fetches EKS cluster description using the specified profile."""
    cmd = f"aws eks describe-cluster --name {cluster_name} --region {region} --output json"
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
    output_list = run_cmd(cmd_list, profile=profile)
    data_list = parse_json(output_list, cmd_list)
    if not data_list or not data_list.get('nodegroups'):
        logging.info(f"No managed nodegroups found (profile: {profile or 'default'}).")
        return nodegroups

    for ng_name in data_list['nodegroups']:
        cmd_desc = f"aws eks describe-nodegroup --cluster-name {cluster_name} --nodegroup-name {ng_name} --region {region} --output json"
        output_desc = run_cmd(cmd_desc, profile=profile)
        data_desc = parse_json(output_desc, cmd_desc)
        if data_desc and data_desc.get('nodegroup'):
            nodegroups.append(data_desc['nodegroup'])
        else:
            logging.warning(f"Could not describe nodegroup '{ng_name}' (profile: {profile or 'default'}).")
    return nodegroups

def get_aws_ec2_instance_metadata_options(instance_id, region, profile=None):
    """Checks EC2 instance metadata options (IMDSv2) using the specified profile."""
    cmd = f"aws ec2 describe-instances --instance-ids {instance_id} --region {region} --query 'Reservations[*].Instances[*].MetadataOptions' --output json"
    output = run_cmd(cmd, profile=profile, suppress_error=True)
    if output:
        data = parse_json(output, cmd)
        if data and len(data) > 0 and len(data[0]) > 0 and data[0][0]:
             return data[0][0]
    return None

def get_aws_iam_role_policy_details(role_name, profile=None):
    """ Fetches attached and inline policies for an IAM role using the specified profile. """
    policies = {'Attached': [], 'Inline': {}}
    cmd_attached = f"aws iam list-attached-role-policies --role-name {role_name} --output json"
    output_attached = run_cmd(cmd_attached, profile=profile, suppress_error=True)
    data_attached = parse_json(output_attached, cmd_attached)
    if data_attached and 'AttachedPolicies' in data_attached:
        for policy in data_attached['AttachedPolicies']:
             policies['Attached'].append(policy['PolicyArn'])

    cmd_inline_names = f"aws iam list-role-policies --role-name {role_name} --output json"
    output_inline_names = run_cmd(cmd_inline_names, profile=profile, suppress_error=True)
    data_inline_names = parse_json(output_inline_names, cmd_inline_names)
    if data_inline_names and 'PolicyNames' in data_inline_names:
        for policy_name in data_inline_names['PolicyNames']:
            cmd_inline_policy = f"aws iam get-role-policy --role-name {role_name} --policy-name {policy_name} --output json"
            output_inline_policy = run_cmd(cmd_inline_policy, profile=profile, suppress_error=True)
            data_inline_policy = parse_json(output_inline_policy, cmd_inline_policy)
            if data_inline_policy and 'PolicyDocument' in data_inline_policy:
                 try:
                    # IAM Policy documents are URL encoded JSON strings
                    policy_doc_str = urllib.parse.unquote(data_inline_policy['PolicyDocument'])
                    policies['Inline'][policy_name] = json.loads(policy_doc_str)
                 except Exception as e:
                      logging.error(f"Failed to decode/parse inline policy {policy_name} for role {role_name}: {e}")
                      policies['Inline'][policy_name] = {"Error": "Could not parse policy document"}

    return policies


# --- Kubernetes Analysis Functions ---

# MODIFIED: Added quota and limit checks
def analyze_namespaces(all_findings, namespaces, resource_quotas, limit_ranges):
    logging.info("Analyzing Namespaces (including ResourceQuotas, LimitRanges)...")
    system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'} # Set for faster lookup

    # Create maps for quick lookup of quotas/limits per namespace
    quotas_by_ns = {}
    for rq in resource_quotas:
        ns = rq.get('metadata', {}).get('namespace')
        if ns:
            quotas_by_ns[ns] = quotas_by_ns.get(ns, 0) + 1

    limits_by_ns = {}
    for lr in limit_ranges:
        ns = lr.get('metadata', {}).get('namespace')
        if ns:
            limits_by_ns[ns] = limits_by_ns.get(ns, 0) + 1

    for ns_item in namespaces:
        metadata = ns_item.get('metadata', {})
        ns_name = metadata.get('name')
        labels = metadata.get('labels', {})

        # Skip system namespaces for quota/limit/PSA checks
        if ns_name in system_namespaces:
            continue

        # --- ResourceQuota Check ---
        if ns_name not in quotas_by_ns:
             add_finding(all_findings, SEVERITY_LOW, "Namespace Lacks ResourceQuota",
                         f"Namespace '{ns_name}' does not have any ResourceQuota objects defined. This can lead to resource contention issues or potential DoS if workloads consume excessive resources.",
                         "Define appropriate ResourceQuotas for the namespace to limit the total amount of CPU, memory, storage, and object counts that can be consumed.",
                         "Best Practice / Resource Management", ns_name, ns_name, "Namespace")

        # --- LimitRange Check ---
        if ns_name not in limits_by_ns:
            add_finding(all_findings, SEVERITY_LOW, "Namespace Lacks LimitRange",
                        f"Namespace '{ns_name}' does not have any LimitRange objects defined. This means default resource requests/limits are not enforced for containers, potentially leading to resource exhaustion or scheduling issues.",
                        "Define a LimitRange for the namespace to set default CPU/memory requests and limits for containers, and potentially enforce min/max values.",
                        "Best Practice / Resource Management", ns_name, ns_name, "Namespace")

        # --- PSA Check (Existing) ---
        psa_enforce_label = labels.get('pod-security.kubernetes.io/enforce')
        expected_level = 'restricted' # Or baseline, depending on policy
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


# --- analyze_pods (no changes needed) ---
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
                            f"Pod '{name}' in namespace '{ns}' uses IAM role '{iam_role_arn}' which might have excessive permissions (contains 'admin' or '*').",
                            "Review and apply least privilege to the IAM role associated via IRSA.",
                            "CIS 5.1.5", ns, name, "Pod")
            # Add informational finding for tracking IRSA usage
            add_finding(all_findings, SEVERITY_INFO, "Pod Using IRSA",
                         f"Pod '{name}' in namespace '{ns}' uses IAM role via IRSA: {iam_role_arn}",
                         "Ensure the associated IAM role follows the principle of least privilege.",
                         "AWS Best Practice", ns, name, "Pod")

        # Host Network
        if spec.get('hostNetwork', False):
            add_finding(all_findings, SEVERITY_HIGH, "Pod Using Host Network",
                        f"Pod '{name}' in namespace '{ns}' is configured with hostNetwork: true.",
                        "Avoid using hostNetwork. If required, isolate the node.",
                        "CIS 5.2.4", ns, name, "Pod") # Updated CIS ref

        # Host PID/IPC
        if spec.get('hostPID', False):
            add_finding(all_findings, SEVERITY_MEDIUM, "Pod Using Host PID Namespace",
                        f"Pod '{name}' in namespace '{ns}' is configured with hostPID: true.",
                        "Avoid using hostPID unless essential.",
                        "CIS 5.2.3", ns, name, "Pod")
        if spec.get('hostIPC', False):
             add_finding(all_findings, SEVERITY_MEDIUM, "Pod Using Host IPC Namespace",
                        f"Pod '{name}' in namespace '{ns}' is configured with hostIPC: true.",
                        "Avoid using hostIPC unless essential.",
                        "CIS 5.2.2", ns, name, "Pod")


        # HostPath Volumes
        if spec.get('volumes'):
            for volume in spec.get('volumes', []):
                host_path = volume.get('hostPath')
                if host_path:
                    path = host_path.get('path', '')
                    severity = SEVERITY_MEDIUM
                    details = f"Pod '{name}' in namespace '{ns}' uses hostPath volume: '{path}'."
                    if path in sensitive_hostpaths or path.startswith('/var/run'): # Simple check for sensitive paths
                         severity = SEVERITY_HIGH
                         details = f"Pod '{name}' in namespace '{ns}' uses sensitive hostPath volume: '{path}'."

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
            # Get security context: container > pod > default ({})
            pod_sc = spec.get('securityContext', {})
            container_sc = container.get('securityContext', pod_sc) # Inherit from pod if container doesn't specify

            if container_sc.get('privileged', False):
                add_finding(all_findings, SEVERITY_CRITICAL, "Privileged Container",
                            f"Container '{c_name}' in pod '{name}' (namespace '{ns}') is running in privileged mode.",
                            "Do not run privileged containers. Refactor the application if possible.",
                            "CIS 5.2.5", ns, full_name, "Container") # Updated CIS Ref

            # Run as Root User
            run_as_non_root = container_sc.get('runAsNonRoot') # Check combined context
            run_as_user = container_sc.get('runAsUser')

            # Explicitly running as root user 0
            if run_as_user == 0:
                add_finding(all_findings, SEVERITY_MEDIUM, "Container Running As Root",
                            f"Container '{c_name}' in pod '{name}' (namespace '{ns}') is explicitly configured to run as root (runAsUser: 0).",
                            "Configure container's securityContext with runAsNonRoot: true and specify a runAsUser > 0.",
                            "CIS 5.2.6", ns, full_name, "Container")
            # Allowed to run as root (runAsNonRoot: false), even if runAsUser isn't 0
            elif run_as_non_root is False:
                 add_finding(all_findings, SEVERITY_MEDIUM, "Container Allowed to Run As Root",
                            f"Container '{c_name}' in pod '{name}' (namespace '{ns}') is explicitly allowed to run as root (runAsNonRoot: false).",
                            "Set securityContext.runAsNonRoot: true.",
                            "CIS 5.2.6", ns, full_name, "Container")
            # Default case: neither runAsNonRoot nor runAsUser is set -> might run as root depending on image
            elif run_as_non_root is None and run_as_user is None:
                 add_finding(all_findings, SEVERITY_LOW, "Container May Run As Root",
                            f"Container '{c_name}' in pod '{name}' (namespace '{ns}') has no runAsNonRoot or runAsUser specified (default allows root). Image may run as root.",
                            "Explicitly set securityContext.runAsNonRoot: true and specify a runAsUser > 0.",
                            "CIS 5.2.6", ns, full_name, "Container")


            # Missing Resource Limits
            resources = container.get('resources', {})
            limits = resources.get('limits')
            if not limits or not limits.get('cpu') or not limits.get('memory'):
                add_finding(all_findings, SEVERITY_LOW, "Container Missing Resource Limits",
                            f"Container '{c_name}' in pod '{name}' (namespace '{ns}') lacks CPU and/or memory limits.",
                            "Define CPU and memory limits for all containers.",
                            "CIS 5.5.1", ns, full_name, "Container") # Updated CIS Ref

            # AllowPrivilegeEscalation (Defaults to true if not set)
            # Check container SC first, then pod SC
            ape_container = container.get('securityContext', {}).get('allowPrivilegeEscalation')
            ape_pod = spec.get('securityContext', {}).get('allowPrivilegeEscalation', True) # Pod default is True
            allow_privilege_escalation = ape_container if ape_container is not None else ape_pod

            if allow_privilege_escalation: # Catches True and None (default case)
                add_finding(all_findings, SEVERITY_MEDIUM, "Container Allows Privilege Escalation",
                            f"Container '{c_name}' in pod '{name}' (namespace '{ns}') allows privilege escalation (allowPrivilegeEscalation is not set to false).",
                            "Set securityContext.allowPrivilegeEscalation: false.",
                            "CIS 5.2.8", ns, full_name, "Container")

            # ReadOnly Root Filesystem
            # Check container SC first, then pod SC
            ro_container = container.get('securityContext', {}).get('readOnlyRootFilesystem')
            ro_pod = spec.get('securityContext', {}).get('readOnlyRootFilesystem', False) # Pod default is False
            read_only_root_filesystem = ro_container if ro_container is not None else ro_pod

            if not read_only_root_filesystem:
                 add_finding(all_findings, SEVERITY_LOW, "Container Root Filesystem Writable",
                             f"Container '{c_name}' in pod '{name}' (namespace '{ns}') does not have a read-only root filesystem.",
                             "Set securityContext.readOnlyRootFilesystem: true and use volumeMounts for writable directories.",
                             "CIS 5.2.7", ns, full_name, "Container")


            # Image Checks
            image = container.get('image', '')
            if ':' not in image or ':latest' in image.lower(): # Handle case sensitivity
                 add_finding(all_findings, SEVERITY_LOW, "Image Uses Latest Tag",
                             f"Container '{c_name}' in pod '{name}' (namespace '{ns}') uses image '{image}' potentially with 'latest' tag or no tag.",
                             "Use specific, immutable image tags (e.g., git SHA or semantic version) instead of 'latest'.",
                             "Best Practice", ns, full_name, "Container")
            # Basic check for known public registries (can be expanded)
            # Allow ECR (amazonaws.com) and common public ones. Flag others.
            allowed_registries = ['amazonaws.com', 'docker.io', 'gcr.io', 'quay.io', 'ghcr.io', 'mcr.microsoft.com']
            registry = image.split('/')[0] if '/' in image else 'docker.io' # Infer docker.io if no registry part
            # Crude check if registry domain isn't in the allowed list
            if '.' in registry and not any(allowed in registry for allowed in allowed_registries):
                 add_finding(all_findings, SEVERITY_LOW, "Image From Potentially Unapproved Registry",
                             f"Container '{c_name}' in pod '{name}' (namespace '{ns}') uses image '{image}' from a potentially non-standard registry ('{registry}').",
                             "Ensure images are pulled only from approved, trusted registries.",
                             "Best Practice / Supply Chain", ns, full_name, "Container")


        # Service Account Usage
        # sa_name = spec.get('serviceAccountName', 'default') # Defaults to 'default' if not specified
        # Covered better in analyze_serviceaccounts

# --- analyze_serviceaccounts (no changes needed) ---
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
                            f"ServiceAccount '{name}' in namespace '{ns}' uses IAM role '{iam_role_arn}' which might have excessive permissions (contains 'admin' or '*').",
                            "Review and apply least privilege to the IAM role associated via IRSA.",
                            "CIS 5.1.5", ns, name, "ServiceAccount")
            add_finding(all_findings, SEVERITY_INFO, "Service Account Using IRSA",
                         f"ServiceAccount '{name}' in namespace '{ns}' uses IAM role via IRSA: {iam_role_arn}",
                         "Ensure the associated IAM role follows the principle of least privilege.",
                         "AWS Best Practice", ns, name, "ServiceAccount")


        # Check automountServiceAccountToken
        automount_token = sa.get('automountServiceAccountToken') # SA level setting
        # Note: Pod spec can override this. This checks the SA default.
        if automount_token is True or automount_token is None: # Default is true
            if name != "default": # Report non-default SAs that automount
                 add_finding(all_findings, SEVERITY_MEDIUM, "Service Account Token Automount Enabled",
                             f"ServiceAccount '{name}' in namespace '{ns}' has automountServiceAccountToken enabled (or default). Tokens might be mounted unnecessarily in pods using this SA.",
                             "Set automountServiceAccountToken: false on the ServiceAccount unless pods using it specifically need the token (prefer mounting projected tokens if needed).",
                             "CIS 5.1.6", ns, name, "ServiceAccount") # Updated CIS Ref
            else: # Special attention to the 'default' SA
                 add_finding(all_findings, SEVERITY_MEDIUM, "Default Service Account Allows Token Automount",
                             f"The 'default' ServiceAccount in namespace '{ns}' allows token automounting by default.",
                             "Explicitly set automountServiceAccountToken: false on the 'default' ServiceAccount and use dedicated SAs for pods.",
                             "CIS 5.1.6", ns, name, "ServiceAccount")

# --- analyze_rbac (no changes needed) ---
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
                             f"ClusterRoleBinding '{crb_name}' grants highly privileged cluster role '{role_name}' to '{full_subject_name}'. Granting cluster-wide admin/edit rights is highly risky.",
                             "Avoid binding cluster-admin or similar roles directly. Use namespace-scoped roles (RoleBinding) or custom cluster roles with least privilege necessary.",
                             "CIS 5.1.1", '(cluster)', crb_name, "ClusterRoleBinding")

        # Check bindings to sensitive system groups/users
        sensitive_subjects = {
            "ServiceAccount:kube-system/default",
            "Group:system:unauthenticated",
            "Group:system:authenticated",
            # "Group:system:masters" # Usually okay for cluster-admin, but check context
        }
        for subject in subjects:
             subject_name = subject.get('name')
             subject_kind = subject.get('kind')
             subject_ns = subject.get('namespace', '')
             full_subject_name = f"{subject_kind}:{subject_name}"
             if subject_kind == "ServiceAccount" and subject_ns:
                 full_subject_name = f"{subject_kind}:{subject_ns}/{subject_name}"

             if full_subject_name in sensitive_subjects and role_name != 'cluster-admin': # Avoid duplicate finding if bound to cluster-admin
                  add_finding(all_findings, SEVERITY_MEDIUM, "ClusterRoleBinding to Sensitive Subject",
                              f"ClusterRoleBinding '{crb_name}' grants cluster role '{role_name}' to potentially sensitive subject '{full_subject_name}'.",
                              "Review bindings to system groups and default service accounts, especially in kube-system. Ensure the granted role is appropriate and necessary.",
                              "CIS 5.1.1 / Best Practice", '(cluster)', crb_name, "ClusterRoleBinding")


    # Analyze RoleBindings (Namespace-level)
    for rb in role_bindings:
        metadata = rb.get('metadata', {})
        rb_name = metadata.get('name')
        ns = metadata.get('namespace')
        role_ref = rb.get('roleRef', {})
        role_kind = role_ref.get('kind') # Role or ClusterRole
        role_name = role_ref.get('name')
        subjects = rb.get('subjects', [])

        # Check for bindings granting cluster-admin (via ClusterRole) or namespace admin/edit (via Role)
        is_cluster_admin_binding = role_kind == "ClusterRole" and role_name == "cluster-admin"
        is_namespace_admin_binding = role_kind == "Role" and role_name in ["admin", "edit"]

        if is_cluster_admin_binding or is_namespace_admin_binding:
             severity = SEVERITY_HIGH if is_cluster_admin_binding else SEVERITY_MEDIUM
             finding_type = "RoleBinding Grants Cluster Admin" if is_cluster_admin_binding else "RoleBinding Grants High Privileges in Namespace"
             details_role_type = "cluster role 'cluster-admin'" if is_cluster_admin_binding else f"role '{role_name}'"

             for subject in subjects:
                 subject_name = subject.get('name')
                 subject_kind = subject.get('kind')
                 add_finding(all_findings, severity, finding_type,
                             f"RoleBinding '{rb_name}' in namespace '{ns}' grants {details_role_type} to {subject_kind} '{subject_name}'. This provides extensive control within the namespace (or cluster if cluster-admin).",
                             "Avoid binding cluster-admin via RoleBindings. Use custom, namespace-scoped Roles with least privilege instead of the built-in admin/edit roles where possible.",
                             "CIS 5.1.1", ns, rb_name, "RoleBinding")

        # Check for bindings involving the default service account
        for subject in subjects:
            if subject.get('kind') == "ServiceAccount" and subject.get('name') == "default":
                 add_finding(all_findings, SEVERITY_MEDIUM, "RoleBinding Involves Default Service Account",
                             f"RoleBinding '{rb_name}' in namespace '{ns}' grants role '{role_name}' (Kind: {role_kind}) to the 'default' ServiceAccount.",
                             "Avoid granting permissions to the 'default' service account. Create and use dedicated service accounts for applications with specific, minimal roles.",
                             "CIS 5.1.3", ns, rb_name, "RoleBinding")

    # Analyze ClusterRoles and Roles for risky permissions
    all_roles = [('ClusterRole', r) for r in cluster_roles] + [('Role', r) for r in roles]
    for role_type, role in all_roles:
        metadata = role.get('metadata', {})
        role_name = metadata.get('name')
        ns = metadata.get('namespace', '(cluster)') # Roles have namespace, ClusterRoles don't
        rules = role.get('rules', [])

        is_default_system_role = role_name.startswith("system:") or role_name in ["cluster-admin", "admin", "edit", "view"]

        for rule_idx, rule in enumerate(rules):
            verbs = rule.get('verbs', [])
            resources = rule.get('resources', [])
            api_groups = rule.get('apiGroups', ['core']) # Default to core group if not specified

            # Check for wildcards
            has_wildcard_verb = "*" in verbs
            has_wildcard_resource = "*" in resources
            has_wildcard_group = "*" in api_groups

            # Check for sensitive verb/resource combinations
            rule_sensitive_verbs = [v for v in verbs if v in sensitive_verbs]
            rule_sensitive_resources = [r for r in resources if r in sensitive_resources]
            has_sensitive_combo = bool(rule_sensitive_verbs) and bool(rule_sensitive_resources)

            finding_details = []
            if has_wildcard_verb: finding_details.append("wildcard verb ('*')")
            if has_wildcard_resource: finding_details.append("wildcard resource ('*')")
            if has_wildcard_group: finding_details.append("wildcard apiGroup ('*')")
            if has_sensitive_combo: finding_details.append(f"sensitive verbs ({rule_sensitive_verbs}) on sensitive resources ({rule_sensitive_resources})")

            if finding_details:
                # Determine severity based on scope and type of risky permission
                severity = SEVERITY_LOW
                if has_wildcard_verb or has_wildcard_resource or has_wildcard_group:
                    severity = SEVERITY_MEDIUM
                # Escalate if it's a ClusterRole or grants pod exec/impersonate/bind/escalate
                if role_type == 'ClusterRole':
                     severity = max(severity, SEVERITY_MEDIUM) # At least Medium for ClusterRoles
                if any(v in ["impersonate", "bind", "escalate"] for v in verbs) or \
                   (any(v in ["create", "patch", "update"] for v in verbs) and "pods/exec" in resources):
                     severity = max(severity, SEVERITY_HIGH) # High risk permissions

                # Reduce noise for known default roles unless extremely permissive (e.g., wildcard across verb/resource/group)
                is_extremely_permissive = has_wildcard_verb and has_wildcard_resource and has_wildcard_group
                if not is_default_system_role or is_extremely_permissive:
                    details_str = f"{role_type} '{role_name}' (namespace: {ns}) contains rule {rule_idx+1} with potentially risky permissions: {', '.join(finding_details)}."
                    add_finding(all_findings, severity, "Role Contains Risky Permissions",
                                details_str,
                                f"Review the permissions granted by {role_type} '{role_name}', particularly rule {rule_idx+1}. Apply the principle of least privilege, avoiding wildcards and overly broad sensitive permissions.",
                                "CIS 5.1.2", ns, role_name, role_type)

# --- analyze_network_policies (no changes needed) ---
def analyze_network_policies(all_findings, network_policies_by_ns, all_namespaces):
    logging.info("Analyzing Network Policies...")
    namespaces_with_policies = set(network_policies_by_ns.keys())
    all_ns_names = {ns.get('metadata', {}).get('name') for ns in all_namespaces}
    system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'}

    # Check namespaces without any network policies
    for ns_name in all_ns_names:
        if ns_name not in namespaces_with_policies and ns_name not in system_namespaces:
            add_finding(all_findings, SEVERITY_MEDIUM, "Namespace Lacks Network Policy",
                        f"Namespace '{ns_name}' has no NetworkPolicy defined. By default, all pods within the namespace can communicate with each other, and potentially with pods in other namespaces or external services, violating the principle of least privilege.",
                        "Implement NetworkPolicies to restrict pod-to-pod communication. Start with a default deny policy for the namespace and explicitly allow required ingress/egress traffic between specific pods or namespaces.",
                        "CIS 5.3.2", ns_name, ns_name, "Namespace")

    # Analyze existing policies (basic checks)
    for ns, policies in network_policies_by_ns.items():
        has_default_deny = False # Check per namespace
        for policy in policies:
             metadata = policy.get('metadata', {})
             policy_name = metadata.get('name')
             spec = policy.get('spec', {})

             # Check for default deny (applies to all pods, denies all ingress/egress)
             pod_selector = spec.get('podSelector')
             if pod_selector is not None and not pod_selector: # Empty podSelector means applies to all pods in ns
                 policy_types = spec.get('policyTypes', ['Ingress']) # Default is Ingress if not specified
                 is_ingress_deny = 'Ingress' in policy_types and 'ingress' not in spec
                 is_egress_deny = 'Egress' in policy_types and 'egress' not in spec

                 if is_ingress_deny and is_egress_deny : has_default_deny = True # Found explicit default deny for this ns

             # Check for overly broad allow rules (e.g., allowing from any namespace or any pod)
             ingress_rules = spec.get('ingress', [])
             for rule_idx, rule in enumerate(ingress_rules):
                 from_rules = rule.get('from', [{}]) # If 'from' omitted, it allows all. Treat as [{}] for check.
                 ports = rule.get('ports') # Check if ports are specified

                 for from_rule_idx, from_rule in enumerate(from_rules):
                     # Combine checks for broad selectors
                     pod_selector_all = from_rule.get('podSelector') == {}
                     ns_selector_all = from_rule.get('namespaceSelector') == {}
                     ip_block_all = from_rule.get('ipBlock', {}).get('cidr') == '0.0.0.0/0'

                     # Check if 'from' allows all pods/namespaces/ips without specific selectors
                     if not from_rule: # Empty {} in 'from' list allows all sources
                          details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1} allows traffic from ALL sources (empty 'from' clause)."
                          add_finding(all_findings, SEVERITY_MEDIUM, "Network Policy Allows All Ingress Sources", details,
                                      "Specify podSelectors, namespaceSelectors, or restrictive ipBlocks in ingress rules to limit allowed sources based on least privilege.",
                                      "CIS 5.3.1", ns, policy_name, "NetworkPolicy")
                     elif pod_selector_all:
                          details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1}, from rule #{from_rule_idx+1}, allows traffic from ALL pods in selected namespaces (empty podSelector)."
                          add_finding(all_findings, SEVERITY_LOW, "Network Policy Allows Ingress From All Pods", details,
                                      "Specify labels in podSelectors to restrict allowed source pods.",
                                      "CIS 5.3.1", ns, policy_name, "NetworkPolicy")
                     elif ns_selector_all:
                           details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1}, from rule #{from_rule_idx+1}, allows traffic from ALL namespaces (empty namespaceSelector)."
                           add_finding(all_findings, SEVERITY_LOW, "Network Policy Allows Ingress From All Namespaces", details,
                                       "Specify labels in namespaceSelectors or specific podSelectors to restrict allowed source namespaces/pods.",
                                       "CIS 5.3.1", ns, policy_name, "NetworkPolicy")
                     elif ip_block_all:
                           details = f"Policy '{policy_name}' (namespace '{ns}') ingress rule #{rule_idx+1}, from rule #{from_rule_idx+1}, allows traffic from ANY IP address (0.0.0.0/0)."
                           add_finding(all_findings, SEVERITY_MEDIUM, "Network Policy Allows Ingress From Any IP", details,
                                       "Restrict ipBlock CIDRs to only necessary source IP ranges. Avoid allowing from 0.0.0.0/0 if possible.",
                                       "CIS 5.3.1", ns, policy_name, "NetworkPolicy")

# --- analyze_secrets_configmaps (no changes needed) ---
def analyze_secrets_configmaps(all_findings, secrets, configmaps):
    logging.info("Analyzing Secrets and ConfigMaps (Basic Checks)...")
    potentially_sensitive_key_patterns = ['password', 'secret', 'token', 'key', 'passwd', 'pwd', 'auth', 'credential', 'apikey', 'access_key', 'secret_key']

    for secret in secrets:
        metadata = secret.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        secret_type = secret.get('type', 'Opaque')

        if secret_type in ['kubernetes.io/basic-auth', 'kubernetes.io/ssh-auth', 'kubernetes.io/dockerconfigjson', 'kubernetes.io/tls']:
             add_finding(all_findings, SEVERITY_INFO, "Potentially Sensitive Secret Type Used",
                         f"Secret '{name}' in namespace '{ns}' has type '{secret_type}', which typically stores credentials or sensitive data.",
                         "Ensure access to this secret is tightly controlled via RBAC. Ensure applications retrieve specific keys if possible, rather than mounting the entire secret.",
                         "Best Practice", ns, name, "Secret")

    for cm in configmaps:
        metadata = cm.get('metadata', {})
        ns = metadata.get('namespace')
        name = cm.get('metadata',{}).get('name')
        data = cm.get('data', {})

        if data: # Only check if data exists
            cm_keys = list(data.keys())
            found_sensitive_keys = [key for key in cm_keys if any(pattern in key.lower() for pattern in potentially_sensitive_key_patterns)]

            if found_sensitive_keys:
                 add_finding(all_findings, SEVERITY_MEDIUM, "Potential Sensitive Data in ConfigMap Keys",
                             f"ConfigMap '{name}' in namespace '{ns}' contains keys that suggest sensitive data might be stored insecurely: {found_sensitive_keys}. ConfigMaps are often less protected by RBAC than Secrets.",
                             "Do not store secrets or sensitive configuration (passwords, tokens, keys) in ConfigMaps. Use Kubernetes Secrets instead and ensure appropriate RBAC.",
                             "CIS 5.4.1", ns, name, "ConfigMap")

# --- AWS EKS Analysis Functions (no changes needed) ---
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
                "Ensure the Kubernetes version is supported and patched. Regularly review EKS platform version updates and plan upgrades before end-of-support.",
                "AWS Best Practice / Version Management", '(cluster)', cluster_name, "EKS Cluster")


    # Endpoint Access
    public_access = config.get('endpointPublicAccess', False)
    private_access = config.get('endpointPrivateAccess', False)
    public_cidrs = config.get('publicAccessCidrs', [])

    if public_access:
        if not public_cidrs or "0.0.0.0/0" in public_cidrs:
             add_finding(all_findings, SEVERITY_HIGH, "EKS Public API Endpoint Open to Internet",
                         f"EKS cluster '{cluster_name}' API endpoint is publicly accessible from all IPs (0.0.0.0/0). This exposes the Kubernetes API server to the internet, increasing the attack surface.",
                         "Restrict public access CIDRs ('publicAccessCidrs') to a minimal set of trusted network ranges. If internal network access is sufficient, disable public access entirely and rely on the private endpoint.",
                         "CIS 1.1.1", '(cluster)', cluster_name, "EKS Cluster")
        else:
             add_finding(all_findings, SEVERITY_LOW, "EKS Public API Endpoint Access Enabled",
                         f"EKS cluster '{cluster_name}' API endpoint is publicly accessible from specific CIDRs: {public_cidrs}.",
                         "Ensure the allowed CIDRs are necessary, restricted to the minimum required ranges, and regularly reviewed. Prefer using the private endpoint ('endpointPrivateAccess: true') where possible.",
                         "CIS 1.1.1", '(cluster)', cluster_name, "EKS Cluster")

    if not private_access and not public_access:
        add_finding(all_findings, SEVERITY_HIGH, "EKS API Endpoint Access Disabled",
                    f"EKS cluster '{cluster_name}' has both public and private API endpoint access disabled. This typically indicates a misconfiguration, making the cluster control plane inaccessible.",
                    "Review cluster configuration. At least one access method (preferably private) must be enabled for the cluster to function correctly.",
                    "AWS Error", '(cluster)', cluster_name, "EKS Cluster")
    elif not private_access and public_access:
         add_finding(all_findings, SEVERITY_MEDIUM, "EKS Private API Endpoint Access Disabled",
                     f"EKS cluster '{cluster_name}' does not have private API endpoint access enabled. Access relies solely on the public endpoint, preventing access from within the VPC without traversing public internet paths.",
                     "Enable private endpoint access ('endpointPrivateAccess: true') for improved security, network isolation, and potentially lower latency access from within the VPC.",
                     "AWS Best Practice / Network Security", '(cluster)', cluster_name, "EKS Cluster")


    # Control Plane Logging
    required_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
    enabled_logs_config = cluster_info.get('logging', {}).get('clusterLogging', []) # List of dicts [{'types': [...], 'enabled': True/False}]
    enabled_logs_flat = set()
    for log_group in enabled_logs_config:
        if log_group.get('enabled'):
            enabled_logs_flat.update(log_group.get('types', []))

    missing_logs = [log for log in required_logs if log not in enabled_logs_flat]
    if missing_logs:
        add_finding(all_findings, SEVERITY_MEDIUM, "EKS Control Plane Logging Disabled",
                    f"EKS cluster '{cluster_name}' does not have all recommended control plane log types enabled. Missing: {', '.join(missing_logs)}. This hinders security auditing, incident response, and operational troubleshooting.",
                    f"Enable all recommended control plane log types ({', '.join(required_logs)}) in the cluster's logging configuration to ensure comprehensive visibility into control plane activities.",
                    "CIS 1.1.2", '(cluster)', cluster_name, "EKS Cluster")
    else:
         add_finding(all_findings, SEVERITY_INFO, "EKS Control Plane Logging Enabled",
                     f"EKS cluster '{cluster_name}' has all recommended control plane log types enabled ({', '.join(required_logs)}).",
                     "Ensure these logs (especially audit logs) are being ingested, monitored, and retained appropriately in CloudWatch Logs or a dedicated SIEM system.",
                     "CIS 1.1.2", '(cluster)', cluster_name, "EKS Cluster")

    # Secrets Encryption
    encryption_config = cluster_info.get('encryptionConfig', [])
    kms_key_arn = None
    secrets_resource_encrypted = False
    if encryption_config:
         for cfg in encryption_config:
             provider_key_arn = cfg.get('provider', {}).get('keyArn')
             if provider_key_arn:
                 kms_key_arn = provider_key_arn # Found a KMS key configured
                 if 'secrets' in cfg.get('resources', []):
                     secrets_resource_encrypted = True
                     break # Found encryption enabled specifically for secrets

    if not kms_key_arn:
         add_finding(all_findings, SEVERITY_HIGH, "EKS Secrets Encryption Not Enabled",
                     f"EKS cluster '{cluster_name}' does not have envelope encryption for Kubernetes secrets enabled using a KMS key. Secrets are stored base64 encoded but unencrypted at rest in etcd.",
                     "Enable envelope encryption using a customer-managed KMS key to protect Kubernetes secrets at rest in the underlying etcd datastore.",
                     "CIS 1.1.3", '(cluster)', cluster_name, "EKS Cluster")
    elif not secrets_resource_encrypted:
         add_finding(all_findings, SEVERITY_HIGH, "EKS Secrets Resource Not Explicitly Encrypted",
                     f"EKS cluster '{cluster_name}' has envelope encryption configured with KMS key '{kms_key_arn}', but the 'secrets' resource is not explicitly listed in the encryption configuration's resources.",
                     "Ensure the 'secrets' resource type is included in the 'resources' list within the EKS encryptionConfig to guarantee secrets are encrypted at rest.",
                     "CIS 1.1.3", '(cluster)', cluster_name, "EKS Cluster")
    else: # Encryption is enabled and includes secrets
         add_finding(all_findings, SEVERITY_INFO, "EKS Secrets Encryption Enabled",
                     f"EKS cluster '{cluster_name}' has envelope encryption enabled for secrets using KMS key: {kms_key_arn}.",
                     "Ensure the KMS key policy follows the principle of least privilege and that key rotation is considered.",
                     "CIS 1.1.3", '(cluster)', cluster_name, "EKS Cluster")

     # Cluster IAM Role Analysis (Basic)
    cluster_role_arn = cluster_info.get('roleArn')
    if cluster_role_arn:
        role_name = cluster_role_arn.split('/')[-1]
        add_finding(all_findings, SEVERITY_INFO, "EKS Cluster IAM Role Identified",
                     f"EKS cluster '{cluster_name}' uses IAM role: {role_name} ({cluster_role_arn}).",
                     "Review the policies attached to this role (e.g., AmazonEKSClusterPolicy). Ensure they are not overly permissive and adhere to least privilege. Consider deeper analysis if IAM permissions allow.",
                     "AWS Best Practice / IAM", '(cluster)', cluster_name, "EKS Cluster IAM Role")

def analyze_eks_nodegroups(all_findings, nodegroups, cluster_name, region):
    logging.info("Analyzing EKS Nodegroups...")
    if not nodegroups:
        logging.info("No managed nodegroups found to analyze.")
        return

    for ng in nodegroups:
        ng_name = ng.get('nodegroupName')
        node_role_arn = ng.get('nodeRole')
        remote_access = ng.get('remoteAccess', {}) # May be missing if no remote access configured
        ec2_ssh_key = remote_access.get('ec2SshKey') if remote_access else None
        source_sgs = remote_access.get('sourceSecurityGroups') if remote_access else [] # Returns list or None

        asset_name = f"{cluster_name}/{ng_name}"
        asset_type = "EKS Nodegroup"

        # Basic info - useful context
        ami_type = ng.get('amiType')
        version_info = ng.get('releaseVersion')
        instance_types = ng.get('instanceTypes')
        add_finding(all_findings, SEVERITY_INFO, "Nodegroup Configuration Info",
                    f"Nodegroup '{ng_name}': AMI Type '{ami_type}', Version '{version_info}', Instances '{','.join(instance_types)}', Node Role '{node_role_arn.split('/')[-1]}'.",
                    "Informational finding detailing the nodegroup configuration.",
                    "N/A", '(cluster)', asset_name, asset_type)


        # Check for Remote SSH Access
        if ec2_ssh_key:
             if not source_sgs: # sourceSecurityGroups is None or empty list
                 add_finding(all_findings, SEVERITY_HIGH, "Nodegroup SSH Access Enabled Without Source Restriction",
                             f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}' but does not restrict access to specific source Security Groups. This likely allows SSH access from any IP address with the key.",
                             "Define specific source Security Groups ('sourceSecurityGroups') for SSH access to restrict it to trusted bastion hosts or administrative networks. Alternatively, disable SSH access ('ec2SshKey: null') if not required.",
                             "CIS 4.1.1", '(cluster)', asset_name, asset_type)
             else:
                 add_finding(all_findings, SEVERITY_MEDIUM, "Nodegroup SSH Access Enabled",
                             f"Nodegroup '{ng_name}' has SSH access enabled via key '{ec2_ssh_key}', restricted to source Security Groups: {source_sgs}.",
                             "Ensure SSH access is necessary and the source security groups allow only minimal required access (e.g., from specific bastion IPs). Regularly rotate SSH keys and disable access if not actively needed.",
                             "CIS 4.1.1", '(cluster)', asset_name, asset_type)
        else:
             add_finding(all_findings, SEVERITY_INFO, "Nodegroup SSH Access Disabled",
                         f"Nodegroup '{ng_name}' does not have EC2 SSH key configured in its remote access settings.",
                         "Direct SSH access to nodes via the EKS nodegroup configuration is disabled. Verify launch template overrides if applicable.",
                         "CIS 4.1.1", '(cluster)', asset_name, asset_type)

        # Check Node IAM Role (Basic)
        if node_role_arn:
             role_name = node_role_arn.split('/')[-1]
             add_finding(all_findings, SEVERITY_INFO, "Nodegroup IAM Role Identified",
                         f"Nodegroup '{ng_name}' uses Node IAM role: {role_name} ({node_role_arn}).",
                         "Review policies attached (e.g., AmazonEKSWorkerNodePolicy, AmazonEC2ContainerRegistryReadOnly, AmazonEKS_CNI_Policy). Ensure no unnecessary permissions (e.g., broad EC2/S3 access). Consider deeper analysis if IAM permissions allow.",
                         "AWS Best Practice / IAM", '(cluster)', asset_name, f"{asset_type} IAM Role")

        # IMDSv2 Check Placeholder
        add_finding(all_findings, SEVERITY_INFO, "IMDSv2 Check Recommended",
                     f"Nodegroup '{ng_name}': Manual check recommended for IMDSv2 enforcement.",
                     "Verify if IMDSv2 is enforced (MetadataHttpTokens=required) on the underlying EC2 instances to mitigate SSRF risks. Check the Launch Template used by the nodegroup or inspect a running instance if EC2 permissions are available.",
                     "CIS 4.1.3", '(cluster)', asset_name, asset_type)


# NEW: Analyze Services and Ingresses for exposure
def analyze_network_exposure(all_findings, services, ingresses):
    logging.info("Analyzing Services and Ingresses for Network Exposure...")

    # Analyze Services
    for svc in services:
        metadata = svc.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        spec = svc.get('spec', {})
        svc_type = spec.get('type')

        if svc_type == 'LoadBalancer':
            ports = spec.get('ports', [])
            port_list = [f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in ports]
            # Attempt to get ELB hostname (might be in status)
            hostname = ""
            try:
                 hostname = svc.get('status', {}).get('loadBalancer', {}).get('ingress', [{}])[0].get('hostname', '')
            except (IndexError, AttributeError, TypeError):
                 pass # Ignore if status is not populated yet or structure differs

            details = (f"Service '{name}' in namespace '{ns}' is of Type LoadBalancer, which provisions an external AWS Load Balancer, exposing the service publicly or internally depending on LB annotations/config. "
                       f"Exposed Ports: {', '.join(port_list) or 'None defined in spec?'}. "
                       f"LoadBalancer Hostname (if available): {hostname or 'N/A'}")
            recommendation = ("Verify that this external exposure is intentional and necessary. "
                              "Ensure appropriate security groups are attached to the load balancer restricting access to trusted sources. "
                              "Consider using Ingress resources or internal load balancers if external exposure is not required. "
                              "Regularly review exposed services.")
            add_finding(all_findings, SEVERITY_MEDIUM, "Service Exposed via LoadBalancer",
                        details, recommendation,
                        "Best Practice / Network Exposure", ns, name, "Service")

    # Analyze Ingresses
    for ing in ingresses:
        metadata = ing.get('metadata', {})
        ns = metadata.get('namespace')
        name = metadata.get('name')
        spec = ing.get('spec', {})
        rules = spec.get('rules', [])
        tls_hosts = {host for tls_entry in spec.get('tls', []) for host in tls_entry.get('hosts', [])} # Set of hosts covered by TLS

        if not rules:
             # Ingress without rules might use default backend, check if default backend is defined
             default_backend = spec.get('defaultBackend')
             if default_backend:
                   add_finding(all_findings, SEVERITY_LOW, "Ingress Uses Default Backend",
                                f"Ingress '{name}' in namespace '{ns}' defines a default backend but has no specific rules. All unmatched traffic will be routed here.",
                                "Ensure the default backend is intended and secured. Define specific rules for expected traffic.",
                                "Best Practice / Configuration", ns, name, "Ingress")
             continue # Skip rule analysis if no rules

        for rule_idx, rule in enumerate(rules):
            host = rule.get('host')
            http_paths = rule.get('http', {}).get('paths', [])

            # Check for Wildcard Host
            if host == '*':
                 details = (f"Ingress '{name}' in namespace '{ns}' rule #{rule_idx+1} uses a wildcard host ('*'). "
                            "This can lead to unintended traffic routing or conflicts if not carefully managed.")
                 recommendation = "Avoid using wildcard hosts in Ingress rules if possible. Use specific hostnames to ensure predictable routing and isolation."
                 add_finding(all_findings, SEVERITY_LOW, "Ingress Rule Uses Wildcard Host",
                             details, recommendation,
                             "Best Practice / Configuration", ns, name, "Ingress")

            # Check for Missing TLS (only if host is defined, ignore wildcard hosts for this check as TLS for wildcard is complex)
            if host and host != '*' and host not in tls_hosts:
                details = (f"Ingress '{name}' in namespace '{ns}' rule #{rule_idx+1} defines host '{host}' but this host is not included in any entry under spec.tls. "
                           "Traffic for this host may be served over unencrypted HTTP.")
                recommendation = (f"Configure TLS for host '{host}' by adding an entry to the Ingress 'spec.tls' section, referencing a valid Kubernetes secret containing the TLS certificate and key. "
                                  "Ensure HTTPS is enforced, potentially via Ingress controller annotations.")
                add_finding(all_findings, SEVERITY_MEDIUM, "Ingress Rule Lacks TLS Configuration",
                           details, recommendation,
                           "Best Practice / Encryption", ns, name, "Ingress")


# --- Reporting ---

def export_findings_to_csv(findings, filename="eks_findings_plextrac.csv"):
    """Exports findings to a CSV file formatted for Plextrac import."""
    if not findings:
        logging.info("No findings to export.")
        return

    fieldnames = [
        "Finding Name", # (Title) -> finding['type']
        "Severity", # finding['severity']
        "Status", # Default 'Open'
        "Description", # finding['details']
        "Recommendation", # finding['recommendation']
        "Vulnerability References", # finding['reference']
        "Affected Components", # -> asset identifier: namespace/name or ARN
        "Tags", # Static + dynamic (e.g., resource type)
    ]

    logging.info(f"Exporting {len(findings)} findings to {filename}...")
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for finding in findings:
                affected_component = f"{finding['namespace']}/{finding['name']}"
                if finding['namespace'] == '(cluster)':
                     affected_component = finding['name']

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
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--context", help="kubectl context to use")
    parser.add_argument("-o", "--output-file", default="eks_findings_plextrac.csv", help="Output CSV file name")
    parser.add_argument("-f", "--output-format", choices=['csv', 'json'], default='csv', help="Output format (csv or json)") # NEW: Output format
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    all_findings = []
    start_time = datetime.now()
    logging.info(f"Starting AWS EKS Security Scanner for cluster '{args.cluster_name}' in region '{args.region}'...")
    logging.info(f"Using AWS Profile: '{args.profile or 'default'}' | Using kubectl Context: '{args.context or 'default'}'")
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
    # TODO: Add EKS Addon fetching: aws eks list-addons, describe-addon

    # 2. Fetch Kubernetes Resources (Efficiently) (pass context)
    logging.info("--- Fetching Kubernetes Resources ---")
    # Combining some fetches for efficiency where possible
    namespaces = get_k8s_resources("namespaces", context=args.context)
    pods = get_k8s_resources("pods", context=args.context, use_all_namespaces=True)
    service_accounts = get_k8s_resources("serviceaccounts", context=args.context, use_all_namespaces=True)
    # Fetch RBAC resources
    roles = get_k8s_resources("roles", context=args.context, use_all_namespaces=True)
    role_bindings = get_k8s_resources("rolebindings", context=args.context, use_all_namespaces=True)
    cluster_roles = get_k8s_resources("clusterroles", context=args.context)
    cluster_role_bindings = get_k8s_resources("clusterrolebindings", context=args.context)
    # Fetch Network related resources
    network_policies_all = get_k8s_resources("networkpolicy", context=args.context, use_all_namespaces=True)
    services = get_k8s_resources("services", context=args.context, use_all_namespaces=True) # Renamed from svc
    ingresses = get_k8s_resources("ingresses", context=args.context, use_all_namespaces=True) # Renamed from ing
    # Fetch Config resources
    secrets = get_k8s_resources("secrets", context=args.context, use_all_namespaces=True)
    configmaps = get_k8s_resources("configmaps", context=args.context, use_all_namespaces=True)
    # Fetch Resource Management resources
    # Using the map return structure here
    res_mgmt_resources = get_k8s_resources("resourcequota,limitrange", context=args.context, use_all_namespaces=True)
    resource_quotas = res_mgmt_resources.get("ResourceQuota", [])
    limit_ranges = res_mgmt_resources.get("LimitRange", [])

    # Pre-process network policies by namespace for easier lookup
    network_policies_by_ns = {}
    for np in network_policies_all:
        ns = np.get('metadata', {}).get('namespace')
        if ns:
            if ns not in network_policies_by_ns:
                network_policies_by_ns[ns] = []
            network_policies_by_ns[ns].append(np)

    # 3. Run Analysis Functions
    logging.info("--- Analyzing Resources ---")
    analyze_eks_cluster_config(all_findings, eks_cluster_info, args.cluster_name, args.region)
    analyze_eks_nodegroups(all_findings, eks_nodegroups, args.cluster_name, args.region)
    # Pass quota/limit data to namespace analysis
    analyze_namespaces(all_findings, namespaces, resource_quotas, limit_ranges)
    analyze_pods(all_findings, pods)
    analyze_serviceaccounts(all_findings, service_accounts)
    analyze_rbac(all_findings, roles, role_bindings, cluster_roles, cluster_role_bindings)
    analyze_network_policies(all_findings, network_policies_by_ns, namespaces)
    # NEW: Call network exposure analysis
    analyze_network_exposure(all_findings, services, ingresses)
    analyze_secrets_configmaps(all_findings, secrets, configmaps)
    # TODO: Add call to analyze EKS Addons

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
        # Sort severities for printing
        sorted_severities = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]
        for sev in sorted_severities:
             if sev in severity_counts:
                 print(f"- {sev}: {severity_counts[sev]}")

        # Export based on selected format
        if args.output_format == 'csv':
            export_findings_to_csv(all_findings, args.output_file)
        elif args.output_format == 'json':
            # Implement JSON export
            logging.info(f"Exporting findings to {args.output_file} in JSON format...")
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    json.dump(all_findings, f, indent=2)
                logging.info(f"Successfully exported findings to {args.output_file}")
            except IOError as e:
                logging.error(f"Failed to write JSON file {args.output_file}: {e}")
            except Exception as e:
                 logging.error(f"An unexpected error occurred during JSON export: {e}")

    else:
        logging.info("No specific security issues found based on the current checks.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--profile", help=argparse.SUPPRESS)
    parser.add_argument("--context", help=argparse.SUPPRESS)
    pre_args, _ = parser.parse_known_args()

    # Use simplified checks here just to see if the commands exist basically
    if run_cmd("kubectl version --client --short", context=pre_args.context, check_rc=False, suppress_error=True) is None:
        logging.warning(f"kubectl command check failed (context: {pre_args.context or 'default'}).")

    if run_cmd("aws sts get-caller-identity", profile=pre_args.profile, check_rc=False, suppress_error=True) is None:
        logging.warning(f"AWS CLI command check failed (profile: {pre_args.profile or 'default'}).")

    main()
