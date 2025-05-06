import csv
import re
from collections import defaultdict
import argparse # Import argparse

# --- Configuration for Roll-up ---
# Columns to use for exact matching to form a group
GROUPING_KEY_COLS = ["Finding Name", "Severity", "Recommendation", "Vulnerability References", "Namespace"]

# For pod/container findings, we also try to group by the "base name" of the pod (controller hint) and container name
POD_ASSET_TYPES = ["Pod", "Container"]

def extract_controller_hint_and_container(affected_component, asset_type):
    """
    Extracts a controller hint (base pod name) and container name.
    Example: "ns/my-deploy-abc-123/my-container" -> ("my-deploy-abc", "my-container")
    Example: "ns/my-daemonset-xyz/my-container" -> ("my-daemonset", "my-container")
    Example: "ns/my-pod-direct" (AssetType Pod) -> ("my-pod-direct", None)
    This is heuristic and might need adjustment based on naming conventions.
    """
    parts = affected_component.split('/')
    # namespace = parts[0] # Namespace is already part of GROUPING_KEY_COLS
    pod_name_full = ""
    container_name = None

    if asset_type == "Container":
        if len(parts) == 3: # ns/pod/container
            pod_name_full = parts[1]
            container_name = parts[2]
        elif len(parts) == 2: # pod/container (assuming (cluster) namespace was handled and this is just pod/container)
             pod_name_full = parts[0]
             container_name = parts[1]
        elif len(parts) == 1: # Only container name if namespace and pod were stripped for (cluster)
            container_name = parts[0] # No pod name to derive controller from in this case
            pod_name_full = "" # Explicitly no pod name if only container name present in component
        else: # fallback
            pod_name_full = parts[-1] # best guess for pod or container

    elif asset_type == "Pod":
        if len(parts) == 2: # ns/pod
            pod_name_full = parts[1]
        elif len(parts) == 1 and parts[0] != "(cluster)": # (cluster)/pod or just pod
            pod_name_full = parts[0]
        else: # (cluster) or unexpected format
            pod_name_full = "" # No usable pod name

    if not pod_name_full: # If pod_name_full is empty (e.g. only container_name was available and it's not a pod)
        return None, container_name # Return None for controller_hint, but still return container_name if found

    # Heuristic: Try to remove common replica/hash suffixes
    match_replicaset = re.match(r'^(.*?)-[a-f0-9]{5,10}-[a-z0-9]{5}$', pod_name_full) # e.g. name-xxxxxxxxx-yyyyy
    match_daemonset_job = re.match(r'^(.*?)-[a-z0-9]{5}$', pod_name_full)         # e.g. name-yyyyy
    match_statefulset = re.match(r'^(.*?)-[0-9]+$', pod_name_full)              # e.g. name-0

    controller_hint = pod_name_full # Default to full pod name if no pattern matches
    if match_replicaset:
        controller_hint = match_replicaset.group(1)
    elif match_statefulset: # Check statefulset before generic daemonset/job pattern
        controller_hint = match_statefulset.group(1)
    elif match_daemonset_job:
        controller_hint = match_daemonset_job.group(1)
    else:
        parts_by_hyphen = pod_name_full.rsplit('-', 1)
        if len(parts_by_hyphen) > 1 and (len(parts_by_hyphen[1]) == 5 and parts_by_hyphen[1].isalnum() or parts_by_hyphen[1].isdigit()):
            controller_hint = parts_by_hyphen[0]
        # If none of the above, controller_hint remains pod_name_full, which is fine for grouping

    return controller_hint, container_name


def rollup_findings(input_csv_path, output_csv_path):
    findings_groups = defaultdict(list)
    fieldnames = [] # To store fieldnames from the input CSV

    try:
        with open(input_csv_path, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            if not reader.fieldnames:
                print(f"Error: Input CSV file '{input_csv_path}' is empty or has no header.")
                return
            fieldnames = reader.fieldnames
            for row in reader:
                # Create a base grouping key
                key_parts = [row[col] for col in GROUPING_KEY_COLS if col in row] # Ensure col exists
                
                # Extract asset type from tags, assuming it's the last tag
                tags_str = row.get("Tags", "")
                asset_type = tags_str.split(',')[-1].strip() if tags_str else "UnknownAsset"


                controller_hint, container_name_key = None, None
                if asset_type in POD_ASSET_TYPES:
                    controller_hint, container_name_key = extract_controller_hint_and_container(row["Affected Components"], asset_type)
                    if controller_hint: # Only add if a valid hint was found
                        key_parts.append(f"controller_hint:{controller_hint}")
                    if container_name_key: # Only add if a valid container name was found
                        key_parts.append(f"container:{container_name_key}")
                
                group_key = tuple(key_parts)
                findings_groups[group_key].append(row)
    except FileNotFoundError:
        print(f"Error: Input file '{input_csv_path}' not found.")
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

        # Create a rolled-up finding
        base_finding = original_findings[0]
        rolled_up = base_finding.copy()
        
        namespace = base_finding["Namespace"]
        tags_str = base_finding.get("Tags", "")
        asset_type_original = tags_str.split(',')[-1].strip() if tags_str else "UnknownAsset"
        
        derived_controller_hint = None
        derived_container_name = None

        key_str_elements = [str(el) for el in group_key_tuple]

        for part in key_str_elements:
            if part.startswith("controller_hint:"):
                derived_controller_hint = part.split(":", 1)[1]
            elif part.startswith("container:"):
                derived_container_name = part.split(":", 1)[1]

        affected_component_summary = namespace
        if derived_controller_hint:
            affected_component_summary += f"/Workload:{derived_controller_hint}"
        elif asset_type_original in POD_ASSET_TYPES : # If it was a pod/container but no controller hint, indicate multiple
            affected_component_summary += f"/Multiple Pods"

        if derived_container_name:
            affected_component_summary += f" (Container: {derived_container_name})"
        elif asset_type_original == "Container" and not derived_container_name:
            # Fallback if container name wasn't picked for key but was original asset type
             affected_component_summary += " (Multiple Containers)"


        rolled_up["Affected Components"] = affected_component_summary


        # Aggregate details into the Description
        description = (
            f"This issue ('{base_finding['Finding Name']}') was observed across multiple instances, "
            f"likely due to a common configuration template within the '{namespace}' namespace"
        )
        if derived_controller_hint:
            description += f" related to workload '{derived_controller_hint}'"
        if derived_container_name:
            description += f" for container(s) named '{derived_container_name}'"
        description += ".\n\nAffected instances and their original specific details include:\n"

        unique_affected_components_details = {}
        for i, finding in enumerate(original_findings):
            original_component_display = finding["Affected Components"].replace(f"{namespace}/", "") # Make it relative for list
            original_detail_text = finding["Description"]
            
            # Shorten the original detail if it's too repetitive with the main finding name
            if original_detail_text.startswith(base_finding['Finding Name']):
                 original_detail_text = original_detail_text[len(base_finding['Finding Name']):].lstrip(':').lstrip()

            formatted_entry = f"- Instance: '{original_component_display}'\n  Detail: {original_detail_text}\n"
            
            if original_component_display not in unique_affected_components_details:
                 unique_affected_components_details[original_component_display] = True # Just mark as seen
                 description += formatted_entry
        
        num_unique_listed = len(unique_affected_components_details)
        if len(original_findings) > num_unique_listed:
            description += f"\n... and {len(original_findings) - num_unique_listed} more instance(s) with similar details to those listed above."


        rolled_up["Description"] = description

        # Update Tags
        tags = base_finding.get("Tags", "").split(',')
        tags = [t.strip() for t in tags if t.strip()] # Clean tags
        tags = [t for t in tags if t not in POD_ASSET_TYPES] 
        
        new_asset_tag = "WorkloadConfiguration" 
        if asset_type_original in POD_ASSET_TYPES and new_asset_tag not in tags:
             tags.append(new_asset_tag)
        if "RolledUp" not in tags:
            tags.append("RolledUp")
        rolled_up["Tags"] = ",".join(tags)

        rolled_up_findings.append(rolled_up)

    # Write the new CSV
    if rolled_up_findings:
        try:
            with open(output_csv_path, mode='w', encoding='utf-8', newline='') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=fieldnames) # Use fieldnames from input
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
        formatter_class=argparse.RawTextHelpFormatter, # To allow newlines in help
        epilog=(
            "Example Usage:\n"
            "  python rollup_eks_findings.py -i initial_findings.csv -o rolled_up_findings.csv\n\n"
            "This script groups findings based on:\n"
            f"  {', '.join(GROUPING_KEY_COLS)}\n"
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
