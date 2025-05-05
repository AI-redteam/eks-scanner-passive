# EKS Scout - AWS EKS Passive Security Scanner

**Version:** 1.1 (Updated: 2025-05-04)

## Overview

EKS Scout is a Python-based security scanner designed for reviewing AWS Elastic Kubernetes Service (EKS) environments. It operates in a **read-only** mode, leveraging `kubectl` and the `aws cli` to passively gather configuration data and identify potential security misconfigurations, vulnerabilities, and deviations from best practices.

This tool is particularly useful for security consultants, auditors, or internal security teams who may have limited, read-only access to an EKS cluster and need to perform a security assessment efficiently.

**Key Features:**

* **Passive Scanning:** Only uses read commands (`get`, `list`, `describe`). No changes are made to the cluster or AWS environment.
* **AWS & Kubernetes Integration:** Checks both EKS-specific configurations via the AWS API and Kubernetes resource configurations via `kubectl`.
* **Multiple Profile/Context Support:** Allows specifying AWS CLI profiles (`--profile`) and `kubectl` contexts (`--context`) for easy use in multi-account/multi-cluster scenarios.
* **Plextrac-Friendly Output:** Generates a CSV report specifically formatted for straightforward import into Plextrac WriteupsDB, streamlining the reporting process.
* **JSON Output:** Optionally outputs findings in JSON format for integration with other tools.
* **Comprehensive Checks:** Covers a range of common security areas (see "Checks Performed" below).

## Prerequisites

Before running EKS Scout, ensure you have the following:

1.  **Python:** Python 3.6 or higher installed.
2.  **kubectl:** The Kubernetes command-line tool (`kubectl`) must be installed and configured with access to the target EKS cluster. You should be able to run basic commands like `kubectl get nodes`.
3.  **AWS CLI:** The AWS Command Line Interface (`aws cli`) must be installed and configured with valid credentials. You should be able to run basic commands like `aws sts get-caller-identity`.
4.  **Permissions:** The credentials used by `kubectl` and `aws cli` need sufficient **read-only** permissions to gather the necessary information.

    * **Kubernetes RBAC Permissions:**
        * Ideally, permissions equivalent to the built-in `view` ClusterRole, applied cluster-wide. This typically includes `get` and `list` permissions on common resources.
        * Specifically, the tool needs to list: `namespaces`, `pods`, `serviceaccounts`, `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`, `networkpolicies`, `services`, `ingresses`, `secrets`, `configmaps`, `resourcequotas`, `limitranges`.
        * Cluster-level access is required to effectively scan all namespaces and cluster-scoped resources.

    * **AWS IAM Permissions:**
        * **Core Required:**
            * `eks:DescribeCluster`
            * `eks:ListNodegroups`
            * `eks:DescribeNodegroup`
            * `sts:GetCallerIdentity` (for credential verification)
        * **Recommended for More Detailed Checks (Optional):**
            * `ec2:DescribeSecurityGroups` (for analyzing Security Group rules)
            * `ec2:DescribeLaunchTemplateVersions` (for checking nodegroup launch template settings like IMDSv2)
            * `iam:ListAttachedRolePolicies`, `iam:GetRolePolicy`, `iam:ListRolePolicies` (for analyzing IAM policies attached to Cluster/Node/IRSA roles)
            * `eks:ListAddons`, `eks:DescribeAddon`, `eks:DescribeAddonVersions` (for checking managed EKS Add-ons)
            * *(Note: The tool will gracefully skip checks if optional permissions are missing)*

## How to Use

1.  **Save the Script:** Save the Python script as `eks_scout.py`.
2.  **Run from Command Line:**

    ```bash
    python eks_scout.py --cluster-name <your-eks-cluster-name> --region <your-aws-region> [options]
    ```

**Required Arguments:**

* `--cluster-name <name>`: The name of the EKS cluster to scan.
* `--region <region>`: The AWS region where the EKS cluster resides (e.g., `us-west-2`).

**Optional Arguments:**

* `--profile <aws-profile>`: Specify the AWS CLI named profile to use for AWS commands. If omitted, uses the default profile/credentials chain.
* `--context <kube-context>`: Specify the `kubectl` context name to use. If omitted, uses the current default context from your KubeConfig.
* `-o <filename>`, `--output-file <filename>`: Specify the name for the output findings file (default: `eks_findings_plextrac.csv`).
* `-f <format>`, `--output-format <format>`: Specify the output format. Choices are `csv` (default) or `json`.
* `--debug`: Enable verbose debug logging, showing commands being run and potentially more detailed error messages.

**Examples:**

```bash
# Scan cluster 'prod-cluster' in 'us-east-1' using defaults
python eks_scout.py --cluster-name prod-cluster --region us-east-1

# Scan using a specific AWS profile and kubectl context
python eks_scout.py --cluster-name dev-cluster --region eu-west-1 --profile dev-account --context dev-eks-context

# Scan and output findings to a specific JSON file
python eks_scout.py --cluster-name staging-cluster --region ap-southeast-2 -o staging_findings.json -f json

# Run with debug logging
python eks_scout.py --cluster-name test-cluster --region us-west-2 --debug
