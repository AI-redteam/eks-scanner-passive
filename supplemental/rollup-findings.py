import csv
import re
from collections import defaultdict
import argparse

# --- Configuration for Roll-up ---
# Columns to use for exact matching to form a group (Namespace will be derived)
GROUPING_KEY_COLS_BASE = ["Finding Name", "Severity", "Recommendation", "Vulnerability References"]

POD_ASSET_TYPES = ["Pod", "Container"]

def extract_namespace_from_component(affected_component_str):
    """
    Extracts namespace from 'ns/name' or 'ns/pod/container'.
    Returns '(cluster)' if no slash is present, assuming it's a cluster-level resource.
    """
    first_slash_index = affected_component_str.find('/')
    if first_slash_index != -1:
        return affected_component_str[:first_slash_index]
    return '(cluster)' # Default for components without a slash (e.g., cluster-level resources)

def extract_controller_hint_and_container(affected_component, asset_type):
    parts = affected_component.split('/')
    pod_name_full = ""
    container_name = None
    # Assuming affected_component for Pod/Container includes namespace if present: ns/pod or ns/pod/container
    # If namespace was (cluster), it might be pod or pod/container

    current_ns = extract_namespace_from_component(affected_component)
    
    # Strip namespace for further processing if it's not (cluster)
    if current_ns != '(cluster)' and affected_component.startswith(current_ns + '/'):
        component_without_ns = affected_component[len(current_ns) + 1:]
    else:
        component_without_ns = affected_component

    parts_no_ns = component_without_ns.split('/')

    if asset_type == "Container":
        if len(parts_no_ns) == 2: # pod/container
            pod_name_full = parts_no_ns[0]
            container_name = parts_no_ns[1]
        elif len(parts_no_ns) == 1: # Only container name (e.g. from a cluster-scoped pod-like CRD that doesn't have a clear pod name)
            container_name = parts_no_ns[0]
            pod_name_full = "" # No pod name to derive controller from
        else:
            # Fallback for unexpected format, try to get last part as container, second last as pod
            if len(parts_no_ns) > 0 : container_name = parts_no_ns[-1]
            if len(parts_no_ns) > 1 : pod_name_full = parts_no_ns[-2]


    elif asset_type == "Pod":
        if len(parts_no_ns) == 1: # pod name
            pod_name_full = parts_no_ns[0]
        else: # Unexpected format for pod after stripping namespace
            pod_name_full = component_without_ns # Best guess

    if not pod_name_full:
        return None, container_name

    match_replicaset = re.match(r'^(.*?)-[a-f0-9]{5,10}-[a-z0-9]{5}$', pod_name_full)
    match_daemonset_job = re.match(r'^(.*?)-[a-z0-9]{5}$', pod_name_full)
    match_statefulset = re.match(r'^(.*?)-[0-9]+$', pod_name_full)

    controller_hint = pod_name_full
    if match_replicaset:
        controller_hint = match_replicaset.group(1)
    elif match_statefulset:
        controller_hint = match_statefulset.group(1)
    elif match_daemonset_job:
        controller_hint = match_daemonset_job.group(1)
    else:
        parts_by_hyphen = pod_name_full.rsplit('-', 1)
        if len(parts_by_hyphen) > 1 and (len(parts_by_hyphen[1]) == 5 and parts_by_hyphen[1].isalnum() or parts_by_hyphen[1].isdigit()):
            controller_hint = parts_by_hyphen[0]

    return controller_hint, container_name


def rollup_findings(input_csv_path, output_csv_path):
    findings_groups = defaultdict(list)
    fieldnames = []

    try:
        with open(input_csv_path, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames:
                print(f"Error: Input CSV file '{input_csv_path}' is empty or has no header.")
                return
            fieldnames = reader.fieldnames
            for row in reader:
                # Extract namespace for grouping key
                current_row_namespace = extract_namespace_from_component(row["Affected Components"])

                key_parts = [row[col] for col in GROUPING_KEY_COLS_BASE if col in row]
                key_parts.append(f"extracted_namespace:{current_row_namespace}") # Add extracted namespace to key

                tags_str = row.get("Tags", "")
                asset_type = tags_str.split(',')[-1].strip() if tags_str else "UnknownAsset"

                controller_hint, container_name_key = None, None
                if asset_type in POD_ASSET_TYPES:
                    # Pass the already extracted namespace for context if needed by the function,
                    # but the function will re-evaluate based on Affected Components string.
                    controller_hint, container_name_key = extract_controller_hint_and_container(row["Affected Components"], asset_type)
                    if controller_hint:
                        key_parts.append(f"controller_hint:{controller_hint}")
                    if container_name_key:
                        key_parts.append(f"container:{container_name_key}")
                
                group_key = tuple(key_parts)
                findings_groups[group_key].append(row)
    except FileNotFoundError:
        print(f"Error: Input file '{input_csv_path}' not found.")
        return
    except KeyError as e:
        print(f"Error: Missing expected column in input CSV: {e}. Ensure EKS Scout output is used.")
        return
    except Exception as e:
        print(f"Error reading input CSV file '{input_csv_path}': {e}")
        return

    rolled_up_findings = []
    total_original_findings = 0
    for group_key_tuple, original_findings in findings_groups.items():
        total_original_findings += len(original_findings)
        if len(original_findings) == 1:
            rolled_up_findings.append(original_findings[0])
            continue

        base_finding = original_findings[0]
        rolled_up = base_finding.copy()
        
        # Use the namespace extracted for the group (it's consistent within the group)
        # Find it from the group_key_tuple (the part that starts with "extracted_namespace:")
        group_namespace = '(cluster)' # default
        for key_part_str in group_key_tuple:
            if isinstance(key_part_str, str) and key_part_str.startswith("extracted_namespace:"):
                group_namespace = key_part_str.split(":", 1)[1]
                break
        
        tags_str = base_finding.get("Tags", "")
        asset_type_original = tags_str.split(',')[-1].strip() if tags_str else "UnknownAsset"
        
        derived_controller_hint = None
        derived_container_name = None

        for part_str in group_key_tuple: # group_key_tuple elements are already strings or were converted
             if isinstance(part_str, str):
                if part_str.startswith("controller_hint:"):
                    derived_controller_hint = part_str.split(":", 1)[1]
                elif part_str.startswith("container:"):
                    derived_container_name = part_str.split(":", 1)[1]

        affected_component_summary = group_namespace # Start with the derived namespace for the group
        if derived_controller_hint:
            affected_component_summary += f"/Workload:{derived_controller_hint}"
        elif asset_type_original in POD_ASSET_TYPES :
            affected_component_summary += f"/Multiple Pods"
        # If not a pod/container type and not cluster, ensure the base name isn't lost
        elif group_namespace != '(cluster)' and "/" not in affected_component_summary:
            # This case is tricky: if it's a namespaced item that isn't a pod/container
            # and has no controller hint, the affected_component_summary might just be the namespace.
            # We might need to append a generic placeholder or the first part of the original affected component name.
            # For now, this should be okay as non-pod/container items are less likely to roll up massively.
            # If "Affected Components" was just "ns1/my-role", and group_namespace is "ns1",
            # we should reflect "my-role" somehow.
            # Let's try to reconstruct:
            original_base_name = base_finding["Affected Components"]
            if original_base_name.startswith(group_namespace + "/"):
                original_base_name_part = original_base_name[len(group_namespace)+1:]
                if "/" not in affected_component_summary: # Avoid double slashes or if already complex
                     affected_component_summary += f"/{original_base_name_part.split('/')[0]}" # take first part after ns


        if derived_container_name:
            affected_component_summary += f" (Container: {derived_container_name})"
        elif asset_type_original == "Container" and not derived_container_name:
             affected_component_summary += " (Multiple Containers)"


        rolled_up["Affected Components"] = affected_component_summary

        description = (
            f"This issue ('{base_finding['Finding Name']}') was observed across multiple instances, "
            f"likely due to a common configuration template within the '{group_namespace}' namespace"
        )
        if derived_controller_hint:
            description += f" related to workload '{derived_controller_hint}'"
        if derived_container_name:
            description += f" for container(s) named '{derived_container_name}'"
        description += ".\n\nAffected instances and their original specific details include:\n"

        unique_affected_components_details = {}
        for i, finding in enumerate(original_findings):
            original_component_display = finding["Affected Components"]
            # Make display relative if it's in the same namespace for cleaner list
            if group_namespace != '(cluster)' and original_component_display.startswith(group_namespace + "/"):
                 original_component_display = original_component_display[len(group_namespace)+1:]


            original_detail_text = finding["Description"]
            
            if original_detail_text.startswith(base_finding['Finding Name']):
                 original_detail_text = original_detail_text[len(base_finding['Finding Name']):].lstrip(':').lstrip()

            formatted_entry = f"- Instance: '{original_component_display}' (Original Full Path: {finding['Affected Components']})\n  Detail: {original_detail_text}\n"
            
            if finding["Affected Components"] not in unique_affected_components_details: # Use full original path for uniqueness
                 unique_affected_components_details[finding["Affected Components"]] = True
                 description += formatted_entry
        
        num_unique_listed = len(unique_affected_components_details)
        if len(original_findings) > num_unique_listed:
            description += f"\n... and {len(original_findings) - num_unique_listed} more instance(s) with similar details to those listed above."

        rolled_up["Description"] = description

        tags = base_finding.get("Tags", "").split(',')
        tags = [t.strip() for t in tags if t.strip()]
        tags = [t for t in tags if t not in POD_ASSET_TYPES] 
        
        new_asset_tag = "WorkloadConfiguration" 
        if asset_type_original in POD_ASSET_TYPES and new_asset_tag not in tags:
             tags.append(new_asset_tag)
        if "RolledUp" not in tags:
            tags.append("RolledUp")
        rolled_up["Tags"] = ",".join(tags)

        rolled_up_findings.append(rolled_up)

    if rolled_up_findings:
        try:
            with open(output_csv_path, mode='w', encoding='utf-8', newline='') as outfile:
                if not fieldnames: # Should have been set if input file was processed
                    print("Error: Could not determine fieldnames from input CSV. Cannot write output.")
                    return
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rolled_up_findings)
            print(f"Rolled-up findings written to {output_csv_path}")
            print(f"Original total findings processed: {total_original_findings}. Number of groups: {len(findings_groups)}. Rolled up to: {len(rolled_up_findings)} findings.")
        except IOError as e:
            print(f"Error writing output CSV file '{output_csv_path}': {e}")
        except Exception as e:
            print(f"An unexpected error occurred during CSV writing: {e}")
    else:
        print(f"No findings found in '{input_csv_path}' to process or roll up.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Rolls up EKS Scout findings from a CSV file to group similar findings.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Example Usage:\n"
            "  python rollup_eks_findings.py -i initial_findings.csv -o rolled_up_findings.csv\n\n"
            "This script groups findings based on:\n"
            f"  {', '.join(GROUPING_KEY_COLS_BASE)}, and the derived Namespace.\n"
            "For Pod/Container asset types, it also attempts to group by an inferred controller/workload name\n"
            "and the specific container name to consolidate issues stemming from common templates.\n"
            "The 'Description' of rolled-up findings will list the original affected components and their details."
        )
    )
    parser.add_argument(
        '-i', '--input',
        required=True,
        help="Path to the input CSV file generated by EKS Scout."
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help="Path for the new CSV file with rolled-up findings."
    )

    args = parser.parse_args()
    rollup_findings(args.input, args.output)
