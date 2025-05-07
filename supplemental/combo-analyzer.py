#!/usr/bin/env python3

import csv
import argparse
import re
from collections import defaultdict
from datetime import datetime

# --- Configuration: Define High-Risk Finding Combinations ---

# Findings that indicate a container might run as root
ROOT_CONTAINER_FINDINGS = {
    "Container Running As Root",
    "Container Allowed to Run As Root",
    "Container May Run As Root",
}

# Define sets of finding types that are particularly dangerous when found together on the SAME POD
# Each tuple contains: ({set of finding names}, "Impact Narrative Template", "Remediation Suggestion Template")
# Remediation templates include a placeholder for internal validation.
VALIDATION_NOTE = "\n\n**Important:** Before implementing changes, please validate these findings and the operational necessity of the current configurations with the relevant internal application and platform teams. Assess the potential impact of remediation steps on application functionality."

HIGH_RISK_POD_COMBINATIONS = [
    # --- Critical Risk Combinations (Potential Host Compromise / Escape) ---
    (
        {"Privileged Container", "Pod Using HostPath Volume"},
        "CRITICAL: Pod runs a Privileged container AND mounts a HostPath volume. Privileged mode removes standard container isolation. Combined with direct host path access (especially sensitive paths like '/' or '/var/run/docker.sock'), this creates a direct path for container escape, host filesystem manipulation, node configuration changes, and potential compromise of other containers or the entire node.",
        f"Address the privileged container setting by modifying the relevant controller's (e.g., Deployment, DaemonSet) pod template to set `securityContext.privileged: false`. Simultaneously, remove or replace the `hostPath` volume mount. If host access is essential, use more secure alternatives like specific PersistentVolumes or evaluate if read-only access (`readOnly: true` on the volumeMount) combined with non-root users significantly reduces risk, though removing privileged mode is paramount.{VALIDATION_NOTE}"
    ),
    (
        {"Privileged Container", "Pod Using Host Network"},
        "CRITICAL: Pod runs a Privileged container AND uses the Host Network namespace. This configuration bypasses standard container network isolation and allows the privileged process potential control over the node's network stack (e.g., iptables, interfaces), facilitating node-level traffic sniffing, spoofing, and bypassing Network Policies.",
        f"The primary remediation is to disable privileged mode by setting `securityContext.privileged: false` in the controller's pod template. Additionally, if possible, disable host network usage by setting `spec.hostNetwork: false`. If host network is claimed to be essential (e.g., for certain CNIs or performance monitoring), this requires significant justification and compensating controls (like node isolation and strict NetworkPolicies), but removing privileged mode remains critical.{VALIDATION_NOTE}"
    ),
    (
        {"Pod Using HostPath Volume", "Container Running As Root"}, # Includes Allowed/May run as root
        "CRITICAL/HIGH: Pod mounts a HostPath volume AND contains a container running effectively as Root. If the hostPath is sensitive (e.g., `/var/run/docker.sock`, `/etc`, `/root`, `/`), root privileges within the container provide the means to directly manipulate critical host files, potentially leading to node configuration changes, credential theft, or container escape. Assess the mounted path's sensitivity.",
        f"Configure the container(s) in this pod's template to run as a non-root user (set `securityContext.runAsNonRoot: true` and `securityContext.runAsUser` to a non-zero ID). Also, critically evaluate the need for the `hostPath` volume. If possible, remove it or replace it with a standard PersistentVolume. If `hostPath` must be used, ensure it mounts the least sensitive path possible and consider using `readOnly: true` if feasible. Running as non-root significantly reduces the risk associated with hostPath mounts.{VALIDATION_NOTE}"
    ),
    (
        {"Pod Using HostPath Volume", "Container Allows Privilege Escalation"}, # Especially if path is sensitive
        "HIGH: Pod mounts a HostPath volume AND contains a container allowing Privilege Escalation. If an attacker gains initial access, the ability to escalate privileges combined with host path access increases the likelihood of successfully manipulating host resources or escaping the container.",
        f"Disable privilege escalation by setting `securityContext.allowPrivilegeEscalation: false` in the container's definition within the controller's pod template. Also, review the necessity and sensitivity of the `hostPath` volume mount. Remove or replace `hostPath` with standard PersistentVolumes where possible, or use `readOnly: true` mounts if applicable.{VALIDATION_NOTE}"
        ),

    # --- High Risk Combinations (Significant Escalation / Lateral Movement Potential) ---
    (
        {"Pod Using Host Network", "Container Running As Root"}, # Includes Allowed/May run as root
        "HIGH: Pod uses the Host Network namespace AND contains a container running effectively as Root. Root privileges combined with host network access allow potential manipulation of node network configurations, easier sniffing of node traffic, direct access to node-level services, and bypassing of pod-specific Network Policies.",
        f"Configure the container(s) in this pod's template to run as a non-root user (`runAsNonRoot: true`, `runAsUser: <non-zero>`). Where possible, avoid using `hostNetwork: true`. If host network access is essential, ensure the container runs as non-root and strong NetworkPolicies or node isolation mechanisms are in place.{VALIDATION_NOTE}"
        ),
    (
        {"Pod Using Host PID Namespace", "Container Running As Root"}, # Includes Allowed/May run as root
        "HIGH: Pod uses the Host PID namespace AND contains a container running effectively as Root. This allows processes within the container (running as root) to see and potentially interact with all other processes on the host node, risking information disclosure and disruption of critical node components.",
        f"Configure the container(s) in this pod's template to run as a non-root user (`runAsNonRoot: true`, `runAsUser: <non-zero>`). Avoid using `hostPID: true` unless absolutely necessary for specific monitoring or debugging tools, and ensure such tools run with minimal privileges (non-root).{VALIDATION_NOTE}"
        ),
    (
        {"Pod IRSA Role Potentially Overly Permissive", "Container Running As Root"}, # Includes Allowed/May run as root
        "HIGH: Pod uses an IRSA role suspected to be overly permissive (e.g., contains 'admin'/* in ARN - requires manual IAM validation) AND contains a container running effectively as Root. If this container is compromised (e.g., via application vulnerability), root privileges make it trivial to access and misuse the powerful AWS credentials provided by the IRSA role.",
        f"Configure the container(s) in this pod's template to run as a non-root user (`runAsNonRoot: true`, `runAsUser: <non-zero>`). Independently, conduct a thorough review of the IAM policies attached to the associated IRSA role and apply the principle of least privilege to restrict its AWS permissions. Running as non-root makes exploiting the container harder, while restricting the IAM role limits the blast radius.{VALIDATION_NOTE}"
        ),
    (
        {"Pod Using Host Network", "Pod Using Host PID Namespace"}, # Any combo of host namespaces increases risk
        "HIGH: Pod utilizes multiple Host namespaces (Network, PID, IPC). Each reduces isolation; combining them significantly increases the attack surface on the node, making container escape, information gathering, or host interference much easier for an attacker within the container.",
        f"Critically evaluate the need for using *any* host namespaces (`hostNetwork`, `hostPID`, `hostIPC`). Refactor the application or choose alternative solutions (e.g., standard networking, sidecar containers for monitoring) that do not require breaking container isolation. If usage is unavoidable, ensure strict compensating controls are in place (non-root users, read-only filesystems, minimal capabilities, NetworkPolicies, node isolation).{VALIDATION_NOTE}"
        ),
     (
        {"Pod Using Host Network", "Pod Using HostPath Volume"},
        "HIGH: Pod utilizes both Host Network and HostPath volumes. This combination reduces isolation on multiple fronts (network and filesystem), significantly increasing the attack surface on the node and the potential impact of a container compromise.",
        f"Avoid using `hostNetwork: true` and `hostPath` volumes together if at all possible. Prioritize removing `hostPath` or replacing it with standard PersistentVolumes. If host network is essential, ensure the hostPath volume is removed or made read-only and mounts the least sensitive path possible. Ensure containers run as non-root.{VALIDATION_NOTE}"
        ),
     (
        {"Pod Using Host PID Namespace", "Pod Using HostPath Volume"},
        "HIGH: Pod utilizes both Host PID namespace and HostPath volumes. This combination allows visibility into host processes and direct access to the host filesystem, significantly increasing the attack surface and potential impact (information disclosure, escape).",
        f"Avoid using `hostPID: true` and `hostPath` volumes together. Prioritize removing the `hostPath` volume or replacing it with standard PersistentVolumes. If host PID access is essential for a specific tool, ensure that tool does not also require host filesystem access and runs with minimal privileges.{VALIDATION_NOTE}"
        ),
    (
        {"Privileged Container"}, # Standalone Privileged
        "HIGH/CRITICAL: Pod runs a Privileged container. This setting disables most container security mechanisms, granting the container extensive access to host devices and kernel capabilities. It significantly increases the risk of container escape and node compromise.",
        f"Disable privileged mode by setting `securityContext.privileged: false` in the controller's pod template. This is a critical security hardening step. Applications requiring privileged access should be heavily scrutinized and alternative solutions sought.{VALIDATION_NOTE}"
        ),
    (
        {"Pod Using HostPath Volume"}, # Standalone HostPath
        "MEDIUM/HIGH: Pod mounts a HostPath volume. The risk depends heavily on the path mounted. Mounting sensitive paths like `/`, `/etc`, `/var/run/docker.sock`, `/root`, or `/proc` poses a high risk.",
        f"Critically evaluate the need for the `hostPath` volume mount identified. Replace with standard PersistentVolumes if possible. If `hostPath` is required, mount the most specific, least sensitive path possible and use `readOnly: true` if the application does not need write access. Ensure containers using it run as non-root.{VALIDATION_NOTE}"
        ),

    # --- Medium Risk Combinations (Amplifiers / Specific Scenarios) ---
     (
         {"Container Allows Privilege Escalation", "Container Running As Root"},
         "MEDIUM: Container runs effectively as Root AND allows privilege escalation. While already root, this explicit allowance might enable specific exploits targeting SUID binaries or kernel vulnerabilities that require the ability to escalate.",
         f"Configure the container to run as non-root (`runAsNonRoot: true`, `runAsUser: <non-zero>`) and explicitly disable privilege escalation (`allowPrivilegeEscalation: false`) in the securityContext within the controller's pod template.{VALIDATION_NOTE}"
        ),
     (
         {"Container Root Filesystem Writable", "Container Running As Root"},
         "MEDIUM: Container runs effectively as Root AND has a Writable Root Filesystem. This makes it easier for an attacker to achieve persistence within the container.",
         f"Configure the container to run as non-root (`runAsNonRoot: true`, `runAsUser: <non-zero>`) and set `readOnlyRootFilesystem: true` in the securityContext within the controller's pod template. Use dedicated `emptyDir` or PersistentVolume mounts for required writable directories.{VALIDATION_NOTE}"
        ),

    # --- Standalone Risk Amplifiers ---
     (
         {"Container Missing Resource Limits"},
         "LOW/MEDIUM (DoS Risk Amplifier): Container lacks CPU and/or Memory limits. This allows the pod to potentially consume excessive node resources. If the application inside is vulnerable or compromised, this could be exploited to cause Denial of Service (DoS).",
         f"Define appropriate CPU and memory `limits` (and ideally `requests`) for all containers within the controller's pod template to prevent resource exhaustion and ensure predictable scheduling and stability.{VALIDATION_NOTE}"
         )
]

# (Keep the get_primary_resource_id function as it was)
def get_primary_resource_id(affected_component_str, asset_type):
    parts = affected_component_str.split('/')
    try:
        if asset_type == "Container":
            if len(parts) == 3: return f"Pod:{parts[0]}/{parts[1]}"
            if len(parts) == 2: return f"Pod:{parts[0]}"
            return f"UnknownContainerFormat:{affected_component_str}"
        elif asset_type == "Pod":
             if len(parts) >= 1: return f"Pod:{affected_component_str}" # Handles ns/pod and just pod
             return f"UnknownPodFormat:{affected_component_str}"
        elif asset_type in ["Service", "Ingress", "RoleBinding", "NetworkPolicy", "ConfigMap", "Secret", "ServiceAccount", "ResourceQuota", "LimitRange"]:
             if len(parts) >= 1: return f"{asset_type}:{affected_component_str}"
        elif asset_type == "Namespace":
            if len(parts) >= 1: return f"Namespace:{parts[0]}"
        elif asset_type in ["ClusterRole", "ClusterRoleBinding"]:
            if len(parts) == 1: return f"{asset_type}:{affected_component_str}"
        elif asset_type in ["EKS Cluster", "EKS Nodegroup", "EKS Cluster IAM Role", "EKS Nodegroup IAM Role"]:
             return f"{asset_type}:{affected_component_str}"
    except Exception as e:
        print(f"[Warning] Error parsing resource ID for '{affected_component_str}' (Type: {asset_type}): {e}")
    return f"Unknown:{affected_component_str}"

# --- Modified Function ---

def generate_narrative_report(input_csv_path, output_md_path):
    """
    Reads EKS Scout CSV findings, analyzes finding combinations per Pod,
    and generates a Markdown narrative report highlighting high-risk resources
    including impact and remediation suggestions.
    """
    findings_by_resource = defaultdict(list)
    all_findings_list = []

    # --- 1. Read CSV and Group by Primary Resource ---
    print(f"Reading findings from: {input_csv_path}")
    try:
        with open(input_csv_path, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames:
                print(f"Error: Input CSV file '{input_csv_path}' is empty or has no header.")
                return
            required_cols = ["Finding Name", "Severity", "Description", "Affected Components", "Tags", "Recommendation", "Vulnerability References"]
            if not all(col in reader.fieldnames for col in required_cols):
                 missing_cols = [col for col in required_cols if col not in reader.fieldnames]
                 print(f"Error: Input CSV is missing required columns: {missing_cols}. Please use the original EKS Scout output.")
                 return

            for row in reader:
                all_findings_list.append(row)
                tags_str = row.get("Tags", "")
                asset_type = tags_str.split(',')[-1].strip() if tags_str else "UnknownAsset"
                resource_id = get_primary_resource_id(row["Affected Components"], asset_type)
                if resource_id and resource_id.startswith("Pod:"):
                    findings_by_resource[resource_id].append(row)

    except FileNotFoundError:
        print(f"Error: Input file '{input_csv_path}' not found.")
        return
    except KeyError as e:
        print(f"Error: Missing expected column in input CSV: {e}. Ensure ORIGINAL EKS Scout output is used.")
        return
    except Exception as e:
        print(f"Error reading input CSV file '{input_csv_path}': {e}")
        return

    print(f"Processed {len(all_findings_list)} total findings.")
    print(f"Grouped findings for {len(findings_by_resource)} distinct Pods.")

    # --- 2. Analyze Combinations and Generate Narrative ---
    narrative_sections = []
    high_risk_resources = []
    resource_risk_levels = {}

    print("Analyzing finding combinations per Pod...")
    for resource_id, findings_list in findings_by_resource.items():
        resource_findings_summary = {f["Finding Name"] for f in findings_list}
        if any(f in ROOT_CONTAINER_FINDINGS for f in resource_findings_summary):
             resource_findings_summary.add("Container Running As Root")

        pod_narratives = []
        pod_remediations = set() # Use set to store unique remediation suggestions
        max_risk_level = 0
        hostpath_details = [f["Description"] for f in findings_list if f["Finding Name"] == "Pod Using HostPath Volume"]
        irsa_role_arns = [f["Description"] for f in findings_list if f["Finding Name"] == "Pod IRSA Role Potentially Overly Permissive"] # Extract role ARNs if needed

        for combo_set, impact_narrative, remediation_suggestion in HIGH_RISK_POD_COMBINATIONS:
            required_for_combo = combo_set.copy()
            if required_for_combo.issubset(resource_findings_summary):
                specific_impact = impact_narrative
                specific_remediation = remediation_suggestion

                # Add context to narratives/remediations
                if "HostPath" in impact_narrative and hostpath_details:
                    paths_found = [match.group(1) for detail in hostpath_details if (match := re.search(r"hostPath volume: '(.*?)'", detail))]
                    specific_impact += f" (Specific paths found: `{'; '.join(paths_found)}`)"
                    # Add path context to remediation too if placeholder exists
                    specific_remediation = specific_remediation.replace("<path>", f"`{'; '.join(paths_found)}`")

                if "IRSA role suspected" in impact_narrative and irsa_role_arns:
                    arns_found = [match.group(1) for detail in irsa_role_arns if (match := re.search(r"uses IAM role '(.*?)'", detail))]
                    specific_impact += f" (Role ARN hint: `{'; '.join(arns_found)}`)"
                    specific_remediation = specific_remediation.replace("<role_arn>", f"`{'; '.join(arns_found)}`")

                pod_narratives.append(specific_impact)
                pod_remediations.add(specific_remediation) # Add unique remediation texts

                if specific_impact.startswith("CRITICAL"): max_risk_level = max(max_risk_level, 3)
                elif specific_impact.startswith("HIGH"): max_risk_level = max(max_risk_level, 2)
                elif specific_impact.startswith("MEDIUM"): max_risk_level = max(max_risk_level, 1)
                else: max_risk_level = max(max_risk_level, 1)

        if pod_narratives:
            resource_risk_levels[resource_id] = max_risk_level
            high_risk_resources.append(resource_id)

            section_header_id = resource_id.replace("Pod:", "").replace("/", "-")
            section = f"### <a name='{section_header_id}'></a>Resource: `{resource_id}`\n\n"
            section += "**Identified Risk Scenarios & Potential Impact:**\n\n"
            pod_narratives_sorted = sorted(pod_narratives, key=lambda x: (
                0 if x.startswith("CRITICAL") else 1 if x.startswith("HIGH") else 2 if x.startswith("MEDIUM") else 3
            ))
            for narrative in pod_narratives_sorted:
                section += f"* {narrative}\n" # Removed extra bolding from narrative string itself

            section += "\n**Suggested Remediation Steps:**\n\n"
            if pod_remediations:
                # Sort remediation suggestions roughly by severity implied by keywords
                sorted_remediations = sorted(list(pod_remediations), key=lambda x: (
                     'privileged' not in x.lower(), # prioritize privileged fixes
                     'hostpath' not in x.lower(),
                     'hostnetwork' not in x.lower(),
                     'non-root' not in x.lower(),
                      x # alphabetical fallback
                 ))
                for remediation in sorted_remediations:
                    section += f"* {remediation}\n" # Includes the VALIDATION_NOTE appended earlier
            else:
                section += f"* No specific remediation templates matched the identified combinations. Review individual finding recommendations below and apply security best practices.{VALIDATION_NOTE}\n"

            section += "\n**Individual Contributing Findings for this Resource:**\n\n"
            severities_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
            sorted_findings = sorted(findings_list, key=lambda x: severities_order.get(x.get('Severity', 'Informational'), 5))
            for finding in sorted_findings:
                component_parts = finding["Affected Components"].split('/')
                specific_detail = ""
                if finding.get("Tags", "").endswith("Container") and len(component_parts) > 0 :
                    container_name_part = component_parts[-1]
                    # Basic check to avoid repeating pod name part if container name wasn't extracted well
                    if len(component_parts) > 1 and container_name_part != component_parts[-2]:
                         specific_detail = f" (Container: `{container_name_part}`)"
                    elif len(component_parts) == 1 : # Case where component might just be container name?
                         specific_detail = f" (Container: `{container_name_part}`)"


                short_desc = finding.get('Description', '[No Description]')
                if len(short_desc) > 250:
                    short_desc = short_desc[:247] + "..."
                section += f"* `[{finding.get('Severity','N/A')}]` **{finding.get('Finding Name','N/A')}**{specific_detail}: {short_desc}\n"
            section += "\n---\n"
            narrative_sections.append((max_risk_level, resource_id, section))

    # --- 3. Write Markdown Output ---
    print(f"Generating narrative report: {output_md_path}")
    try:
        with open(output_md_path, mode='w', encoding='utf-8') as outfile:
            outfile.write("# EKS Scout - Chained Threat & High-Risk Resource Report\n\n")
            outfile.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            outfile.write(f"Source Findings File: `{input_csv_path}`\n\n")
            outfile.write("## Introduction\n\n")
            outfile.write("This report analyzes findings from the EKS Scout scan to identify specific resources (primarily Pods) with **combinations of vulnerabilities** that may represent significantly elevated security risks compared to individual findings alone. These combinations can potentially facilitate attack chains such as container escape, host compromise, lateral movement within the cluster, or privilege escalation.\n\n")
            outfile.write("The following sections highlight specific resources identified as potentially high-risk due to concerning combinations of findings, explain the potential security implications based on the identified patterns, and provide **suggested remediation steps**. **Manual validation and contextual analysis are crucial** to confirm the actual risk posed by these combinations and the applicability of remediation suggestions in the specific environment.\n\n") # Added remediation mention
            outfile.write(f"**Summary:** Identified **{len(high_risk_resources)}** Pod(s) with potential high-risk finding combinations out of {len(findings_by_resource)} Pods analyzed that had findings.\n\n")

            if narrative_sections:
                 outfile.write("## Table of High-Risk Resources\n\n")
                 outfile.write("| Risk Level | Resource ID |\n")
                 outfile.write("| :--------- | :---------- |\n")
                 sorted_sections_toc = sorted(narrative_sections, key=lambda x: (-x[0], x[1]))
                 for risk_level_num, res_id, _ in sorted_sections_toc:
                     level_str = {3: "Critical", 2: "High", 1: "Medium/Low"}.get(risk_level_num, "Unknown")
                     anchor_link = res_id.replace("Pod:", "").replace("/", "-") # Basic anchor link generation
                     outfile.write(f"| {level_str} | [`{res_id}`](#{anchor_link}) |\n")
                 outfile.write("\n---\n\n")

                 outfile.write("## Detailed High-Risk Resource Analysis (Sorted by Potential Severity)\n\n")
                 for _, _, section_content in sorted_sections_toc: # Use the same sorted list
                     outfile.write(section_content)
            else:
                outfile.write("---\n\n")
                outfile.write("## High-Risk Resource Analysis\n\n")
                outfile.write("No specific Pods matching the predefined high-risk combinations were identified in this scan.\n\n")
                outfile.write("*(Note: Review individual High/Critical severity findings from the main EKS Scout report for other potential risks that may not involve combinations.)*\n")

        print(f"Chained threat narrative report written to {output_md_path}")

    except IOError as e:
        print(f"Error writing output Markdown file '{output_md_path}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred during Markdown report generation: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Analyzes EKS Scout CSV findings to identify Pods with high-risk vulnerability combinations and generate a narrative report including remediation suggestions.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Example Usage:\n"
            "  python generate_narrative.py -i initial_findings.csv -o high_risk_report.md\n\n"
            "This script reads the ORIGINAL EKS Scout output (not rolled-up) and looks for combinations\n"
            "of findings on individual Pods that indicate elevated risk (e.g., potential for escape, privesc).\n"
            "It generates a Markdown report summarizing these high-risk Pods, their potential impact, and suggested remediation steps."
        )
    )
    parser.add_argument(
        '-i', '--input',
        required=True,
        help="Path to the **original** input CSV file generated by EKS Scout."
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help="Path for the output Markdown narrative report file."
    )

    args = parser.parse_args()
    generate_narrative_report(args.input, args.output)
