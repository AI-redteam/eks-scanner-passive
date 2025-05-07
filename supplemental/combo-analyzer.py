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
# Each tuple contains: ({set of finding names}, "Impact Narrative Template")
HIGH_RISK_POD_COMBINATIONS = [
    # --- Critical Risk Combinations (Potential Host Compromise / Escape) ---
    ({"Privileged Container", "Pod Using HostPath Volume"},
     "CRITICAL: Pod runs a Privileged container AND mounts a HostPath volume. Privileged mode removes standard container isolation. Combined with direct host path access (especially sensitive paths like '/' or '/var/run/docker.sock'), this creates a direct path for container escape, host filesystem manipulation, node configuration changes, and potential compromise of other containers or the entire node."),
    ({"Privileged Container", "Pod Using Host Network"},
     "CRITICAL: Pod runs a Privileged container AND uses the Host Network namespace. This configuration bypasses standard container network isolation and allows the privileged process potential control over the node's network stack (e.g., iptables, interfaces), facilitating node-level traffic sniffing, spoofing, and bypassing Network Policies."),
    ({"Pod Using HostPath Volume", "Container Running As Root"}, # Includes Allowed/May run as root
     "CRITICAL/HIGH: Pod mounts a HostPath volume AND contains a container running effectively as Root. If the hostPath is sensitive (e.g., `/var/run/docker.sock`, `/etc`, `/root`, `/`), root privileges within the container provide the means to directly manipulate critical host files, potentially leading to node configuration changes, credential theft, or container escape. Assess the mounted path's sensitivity."),
    ({"Pod Using HostPath Volume", "Container Allows Privilege Escalation"}, # Especially if path is sensitive
     "HIGH: Pod mounts a HostPath volume AND contains a container allowing Privilege Escalation. If an attacker gains initial access, the ability to escalate privileges combined with host path access increases the likelihood of successfully manipulating host resources or escaping the container."),

    # --- High Risk Combinations (Significant Escalation / Lateral Movement Potential) ---
    ({"Pod Using Host Network", "Container Running As Root"}, # Includes Allowed/May run as root
     "HIGH: Pod uses the Host Network namespace AND contains a container running effectively as Root. Root privileges combined with host network access allow potential manipulation of node network configurations, easier sniffing of node traffic, direct access to node-level services, and bypassing of pod-specific Network Policies."),
    ({"Pod Using Host PID Namespace", "Container Running As Root"}, # Includes Allowed/May run as root
     "HIGH: Pod uses the Host PID namespace AND contains a container running effectively as Root. This allows processes within the container (running as root) to see and potentially interact with (e.g., signal, debug - if capabilities allow) all other processes on the host node, risking information disclosure and disruption of critical node components."),
    ({"Pod IRSA Role Potentially Overly Permissive", "Container Running As Root"}, # Includes Allowed/May run as root
     "HIGH: Pod uses an IRSA role suspected to be overly permissive (e.g., contains 'admin'/* in ARN - requires manual IAM validation) AND contains a container running effectively as Root. If this container is compromised (e.g., via application vulnerability), root privileges make it trivial to access and misuse the powerful AWS credentials provided by the IRSA role, potentially leading to compromise of related AWS resources (S3, EC2, etc.) or privilege escalation within AWS."),
    ({"Pod Using Host Network", "Pod Using Host PID Namespace"}, # Any combo of host namespaces increases risk
     "HIGH: Pod utilizes multiple Host namespaces (Network, PID, IPC). Each reduces isolation; combining them significantly increases the attack surface on the node, making container escape, information gathering, or host interference much easier for an attacker within the container."),
     ({"Pod Using Host Network", "Pod Using HostPath Volume"}, # Any combo of host namespaces/paths increases risk
     "HIGH: Pod utilizes both Host Network and HostPath volumes. This combination reduces isolation on multiple fronts (network and filesystem), significantly increasing the attack surface on the node and the potential impact of a container compromise."),
     ({"Pod Using Host PID Namespace", "Pod Using HostPath Volume"}, # Any combo of host namespaces/paths increases risk
     "HIGH: Pod utilizes both Host PID namespace and HostPath volumes. This combination allows visibility into host processes and direct access to the host filesystem, significantly increasing the attack surface and potential impact (information disclosure, escape)."),
    ({"Privileged Container"}, # Standalone Privileged is still Critical/High
     "HIGH/CRITICAL: Pod runs a Privileged container. This setting disables most container security mechanisms, granting the container extensive access to host devices and kernel capabilities. It significantly increases the risk of container escape and node compromise, even without other misconfigurations."),
    ({"Pod Using HostPath Volume"}, # Standalone HostPath needs path context
     "MEDIUM/HIGH: Pod mounts a HostPath volume. The risk depends heavily on the path mounted. Mounting sensitive paths like `/`, `/etc`, `/var/run/docker.sock`, `/root`, or `/proc` poses a high risk of information disclosure or host compromise. Less sensitive paths might still pose risks depending on permissions."),

    # --- Medium Risk Combinations (Amplifiers / Specific Scenarios) ---
     ({"Container Allows Privilege Escalation", "Container Running As Root"}, # Includes Allowed/May run as root
      "MEDIUM: Container runs effectively as Root AND allows privilege escalation. While already root, this explicit allowance might enable specific exploits targeting SUID binaries or kernel vulnerabilities that require the ability to escalate, potentially bypassing other security controls like seccomp profiles."),
     ({"Container Root Filesystem Writable", "Container Running As Root"}, # Includes Allowed/May run as root
      "MEDIUM: Container runs effectively as Root AND has a Writable Root Filesystem. This combination makes it easier for an attacker who gains execution to achieve persistence within the container by modifying system files, installing malware, or altering application binaries."),
     # Note: SA Token Automount check requires cross-resource correlation not implemented here yet.

    # --- Standalone Risk Amplifiers ---
     ({"Container Missing Resource Limits"}, # Standalone Resource Limit Issue -> DoS Amplification
      "LOW/MEDIUM (DoS Risk Amplifier): Container lacks CPU and/or Memory limits. This allows the pod to potentially consume excessive node resources. If the application inside is vulnerable or compromised, this could be exploited to cause Denial of Service (DoS) for other workloads on the node or impact node stability.")
]


def get_primary_resource_id(affected_component_str, asset_type):
    """
    Generates a unique ID for the primary resource a finding applies to.
    Format: Type:Namespace/Name or Type:Name for cluster-scoped.
    Focuses on identifying Pods for combination analysis.
    """
    parts = affected_component_str.split('/')
    try:
        if asset_type == "Container":
            # ns/pod/container -> Pod:ns/pod
            if len(parts) == 3: return f"Pod:{parts[0]}/{parts[1]}"
            # pod/container (likely cluster ns or parsing error) -> Pod:pod
            if len(parts) == 2: return f"Pod:{parts[0]}"
            # fallback/unexpected
            return f"UnknownContainerFormat:{affected_component_str}"
        elif asset_type == "Pod":
             # ns/pod -> Pod:ns/pod
             if len(parts) == 2: return f"Pod:{affected_component_str}"
             # pod (cluster) -> Pod:pod
             if len(parts) == 1: return f"Pod:{affected_component_str}"
             return f"UnknownPodFormat:{affected_component_str}"
        # For other types, just return a basic identifier for completeness,
        # even though we currently only analyze Pod combinations.
        elif asset_type in ["Service", "Ingress", "RoleBinding", "NetworkPolicy", "ConfigMap", "Secret", "ServiceAccount", "ResourceQuota", "LimitRange"]:
             if len(parts) >= 1: return f"{asset_type}:{affected_component_str}" # Keep full path ns/name
        elif asset_type == "Namespace":
            if len(parts) >= 1: return f"Namespace:{parts[0]}"
        elif asset_type in ["ClusterRole", "ClusterRoleBinding"]:
            if len(parts) == 1: return f"{asset_type}:{affected_component_str}"
        elif asset_type in ["EKS Cluster", "EKS Nodegroup", "EKS Cluster IAM Role", "EKS Nodegroup IAM Role"]:
             return f"{asset_type}:{affected_component_str}"
    except Exception as e:
        print(f"[Warning] Error parsing resource ID for '{affected_component_str}' (Type: {asset_type}): {e}")
    # Fallback
    return f"Unknown:{affected_component_str}"


def generate_narrative_report(input_csv_path, output_md_path):
    """
    Reads EKS Scout CSV findings, analyzes finding combinations per Pod,
    and generates a Markdown narrative report highlighting high-risk resources.
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
            # Validate required columns exist
            required_cols = ["Finding Name", "Severity", "Description", "Affected Components", "Tags"]
            if not all(col in reader.fieldnames for col in required_cols):
                 missing_cols = [col for col in required_cols if col not in reader.fieldnames]
                 print(f"Error: Input CSV is missing required columns: {missing_cols}. Please use the original EKS Scout output.")
                 return

            for row in reader:
                all_findings_list.append(row)
                tags_str = row.get("Tags", "")
                asset_type = tags_str.split(',')[-1].strip() if tags_str else "UnknownAsset"
                
                # Focus on grouping findings associated with Pods for combination analysis
                resource_id = get_primary_resource_id(row["Affected Components"], asset_type)
                if resource_id and resource_id.startswith("Pod:"):
                    findings_by_resource[resource_id].append(row)
                # Can optionally store non-pod findings elsewhere if needed later
                
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
    resource_risk_levels = {} # Store max risk level found for sorting

    print("Analyzing finding combinations per Pod...")
    for resource_id, findings_list in findings_by_resource.items():
        resource_findings_summary = {f["Finding Name"] for f in findings_list}

        # Normalize root findings for easier checking
        if any(f in ROOT_CONTAINER_FINDINGS for f in resource_findings_summary):
             resource_findings_summary.add("Container Running As Root") # Use normalized name for combo checks

        # Evaluate predefined combinations
        pod_narratives = []
        max_risk_level = 0 # 0: None, 1: Low/Med, 2: High, 3: Critical

        # Extract specific path details for HostPath findings if present
        hostpath_details = [f["Description"] for f in findings_list if f["Finding Name"] == "Pod Using HostPath Volume"]

        for combo_set, narrative_template in HIGH_RISK_POD_COMBINATIONS:
            # Check if all findings in the combo_set are present for this resource
            required_for_combo = combo_set.copy() # Use copy to avoid modifying original set
            
            if required_for_combo.issubset(resource_findings_summary):
                # Add context about the specific hostpath if relevant to the narrative
                specific_narrative = narrative_template
                # Add specific host path info if the narrative mentions HostPath and details exist
                if "HostPath" in narrative_template and hostpath_details:
                    # Extract just the path part for brevity in the narrative summary
                    paths_found = []
                    for detail in hostpath_details:
                        match = re.search(r"hostPath volume: '(.*?)'", detail)
                        if match:
                            paths_found.append(match.group(1))
                        else: # Fallback if description format changed
                            paths_found.append("[path detail in description]")
                    specific_narrative += f" (Specific paths found: `{'; '.join(paths_found)}`)"

                pod_narratives.append(specific_narrative)

                # Track risk level based on narrative prefix
                if specific_narrative.startswith("CRITICAL"): max_risk_level = max(max_risk_level, 3)
                elif specific_narrative.startswith("HIGH"): max_risk_level = max(max_risk_level, 2)
                elif specific_narrative.startswith("MEDIUM"): max_risk_level = max(max_risk_level, 1)
                else: max_risk_level = max(max_risk_level, 1) # Default Low/Med

        # If significant combinations were found, prepare narrative section
        if pod_narratives:
            resource_risk_levels[resource_id] = max_risk_level
            high_risk_resources.append(resource_id)

            # Prepare section content
            # Use resource_id which includes the type prefix, e.g., "Pod:ns/name"
            section_header_id = resource_id.replace("Pod:", "").replace("/", "-") # Create a more URL-friendly ID if needed
            section = f"### <a name='{section_header_id}'></a>Resource: `{resource_id}`\n\n" # Add anchor link
            section += "**Identified Risk Scenarios & Potential Impact:**\n\n"
            
            # Sort narratives by severity: Critical > High > Medium > Other
            pod_narratives_sorted = sorted(pod_narratives, key=lambda x: (
                0 if x.startswith("CRITICAL") else
                1 if x.startswith("HIGH") else
                2 if x.startswith("MEDIUM") else
                3
            ))
            for narrative in pod_narratives_sorted:
                section += f"* **{narrative}**\n"
            
            section += "\n**Individual Contributing Findings for this Resource:**\n\n"
            
            severities_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
            sorted_findings = sorted(findings_list, key=lambda x: severities_order.get(x.get('Severity', 'Informational'), 5))

            for finding in sorted_findings:
                component_parts = finding["Affected Components"].split('/')
                specific_detail = ""
                # Try to extract container name if it's a container-level finding on this pod
                if finding.get("Tags", "").endswith("Container") and len(component_parts) > 1 :
                    container_name_part = component_parts[-1]
                    # Double check it doesn't match the pod name part if parsing was odd
                    if len(component_parts) > 1 and container_name_part != component_parts[-2]:
                         specific_detail = f" (Container: `{container_name_part}`)"
                    elif len(component_parts) == 1 and asset_type == "Container": # Handle case like Container:(cluster)/cont_name ? Less likely.
                         specific_detail = f" (Container: `{component_parts[0]}`)"


                short_desc = finding.get('Description', '[No Description]')
                if len(short_desc) > 250: # Shorten long descriptions in this list
                    short_desc = short_desc[:247] + "..."

                section += f"* `[{finding.get('Severity','N/A')}]` **{finding.get('Finding Name','N/A')}**{specific_detail}: {short_desc}\n"
            section += "\n---\n"
            narrative_sections.append((max_risk_level, resource_id, section)) # Store with risk level and ID for sorting

    # --- 3. Write Markdown Output ---
    print(f"Generating narrative report: {output_md_path}")
    try:
        with open(output_md_path, mode='w', encoding='utf-8') as outfile:
            outfile.write("# EKS Scout - Chained Threat & High-Risk Resource Report\n\n")
            outfile.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            outfile.write(f"Source Findings File: `{input_csv_path}`\n\n")
            outfile.write("## Introduction\n\n")
            outfile.write("This report analyzes findings from the EKS Scout scan to identify specific resources (primarily Pods) with **combinations of vulnerabilities** that may represent significantly elevated security risks compared to individual findings alone. These combinations can potentially facilitate attack chains such as container escape, host compromise, lateral movement within the cluster, or privilege escalation.\n\n")
            outfile.write("The following sections highlight specific resources identified as potentially high-risk due to concerning combinations of findings and explain the potential security implications based on the identified patterns. **Manual validation and contextual analysis are crucial** to confirm the actual risk posed by these combinations in the specific environment.\n\n")
            outfile.write(f"**Summary:** Identified **{len(high_risk_resources)}** Pod(s) with potential high-risk finding combinations out of {len(findings_by_resource)} Pods analyzed that had findings.\n\n")
            
            if narrative_sections:
                 outfile.write("## Table of High-Risk Resources\n\n")
                 outfile.write("| Risk Level | Resource ID |\n")
                 outfile.write("| :--------- | :---------- |\n")
                 # Sort sections by risk level (Critical > High > Medium) then by resource ID
                 sorted_sections = sorted(narrative_sections, key=lambda x: (-x[0], x[1]))
                 for risk_level_num, res_id, _ in sorted_sections:
                     level_str = {3: "Critical", 2: "High", 1: "Medium/Low"}.get(risk_level_num, "Unknown")
                     anchor_link = res_id.replace("Pod:", "").replace("/", "-")
                     outfile.write(f"| {level_str} | [`{res_id}`](#{anchor_link}) |\n")
                 outfile.write("\n---\n\n")
                 
                 outfile.write("## Detailed High-Risk Resource Analysis\n\n")
                 for _, _, section_content in sorted_sections:
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
        description="Analyzes EKS Scout CSV findings to identify Pods with high-risk vulnerability combinations and generate a narrative report.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Example Usage:\n"
            "  python generate_narrative.py -i initial_findings.csv -o high_risk_report.md\n\n"
            "This script reads the ORIGINAL EKS Scout output (not rolled-up) and looks for combinations\n"
            "of findings on individual Pods that indicate elevated risk (e.g., potential for escape, privesc).\n"
            "It generates a Markdown report summarizing these high-risk Pods and their potential impact."
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
