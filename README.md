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

## Checks Performed

EKS Scout performs checks across several categories:

* **EKS Cluster Configuration:**
    * API Server Endpoint Access (Public/Private, CIDR restrictions)
    * Control Plane Logging Enabled (api, audit, authenticator, etc.)
    * Envelope Encryption for Secrets (KMS key usage)
* **EKS Nodegroup Configuration:**
    * SSH Access Configuration (Enabled/Disabled, Source SG restrictions)
    * Node IAM Role Association (Identifies the role for manual review)
    * IMDSv2 Enforcement Check (Recommendation for manual verification or via optional permissions)
* **Kubernetes Namespaces:**
    * Pod Security Admission (PSA) Labels (Presence and level: baseline/restricted)
    * ResourceQuota Existence (Checks if quotas are defined)
    * LimitRange Existence (Checks if limit ranges are defined)
* **Kubernetes Pod Security:**
    * Host Namespace Usage (`hostNetwork`, `hostPID`, `hostIPC`)
    * HostPath Volume Usage (Checks for potentially sensitive mounts)
    * Privileged Containers
    * Running as Root User (`runAsUser: 0`, `runAsNonRoot: false`)
    * Privilege Escalation (`allowPrivilegeEscalation: true`)
    * Writable Root Filesystem (`readOnlyRootFilesystem: false`)
    * Missing Resource Limits (CPU/Memory)
    * Image Provenance (Use of `:latest` tag, potentially unapproved registries)
    * IRSA Role Association (Identifies roles for review)
* **Kubernetes Service Accounts:**
    * IRSA Role Association (Identifies roles for review)
    * Token Automounting (Checks if SA or `default` SA allows automatic token mounting)
* **Kubernetes RBAC (Role-Based Access Control):**
    * Bindings granting cluster-admin or high privileges (admin/edit)
    * Bindings to sensitive subjects (e.g., `system:unauthenticated`, default SAs)
    * Risky permissions within Role/ClusterRole definitions (wildcards, sensitive verbs/resources)
* **Kubernetes Network Policies:**
    * Namespaces lacking any NetworkPolicy
    * Policies allowing overly broad ingress (from any pod/namespace/IP)
* **Kubernetes Network Exposure:**
    * Services of `Type: LoadBalancer` (indicating external exposure)
    * Ingress rules lacking corresponding TLS configuration
    * Ingress rules using wildcard hosts (`*`)
* **Kubernetes Configuration & Secrets:**
    * Basic check for potentially sensitive data stored in ConfigMap keys.
    * Identification of Secrets using common sensitive types (e.g., `kubernetes.io/basic-auth`).

## Plextrac Integration

The default CSV output format is designed for easy import into Plextrac's WriteupsDB. The CSV columns map generally as follows:

* `Finding Name` -> Plextrac **Title**
* `Severity` -> Plextrac **Severity**
* `Status` -> Plextrac **Status** (Defaults to "Open")
* `Description` -> Plextrac **Description**
* `Recommendation` -> Plextrac **Recommendation**
* `Vulnerability References` -> Plextrac **References**
* `Affected Components` -> Plextrac **Location** or **Affected Asset** (Provides Namespace/Name or Cluster resource name)
* `Tags` -> Plextrac **Tags** (Includes "EKS", "Kubernetes", "Security", and the specific Asset Type)

You can typically use the CSV Import feature in Plextrac WriteupsDB and map these columns accordingly.

## Future Additions

EKS Scout can be extended with more checks. Potential areas for future development include:

* **Deeper IAM Policy Analysis:** Parsing IAM policy documents for specific risky permissions (requires more IAM permissions).
* **Deeper Security Group Analysis:** Analyzing SG rules associated with Cluster/Nodes/LoadBalancers (requires EC2 permissions).
* **EKS Add-on Version Checks:** Comparing installed Add-on versions against known vulnerabilities or best practices.
* **Check Deprecated API Usage:** Identify resources using Kubernetes APIs scheduled for removal.
* **More Granular Network Policy Checks.**
* **Support for Self-Managed Nodes.**
* **User-Defined Checks via Configuration Files.**

*(Feel free to contribute or suggest new checks!)*

## Disclaimer

EKS Scout is a tool intended to aid security assessments by identifying potential misconfigurations based on read-only data.

* **Use Responsibly:** Ensure you have authorization to scan the target environment.
* **Read-Only Limitations:** The tool cannot verify runtime security controls or detect all possible vulnerabilities (e.g., application-level flaws, compromised credentials). Findings are based on configuration analysis.
* **Verify Findings:** Always review and validate the findings within the context of the specific environment before taking remediation actions.
* **No Guarantees:** This tool is provided "as is" without warranty of any kind.

Please use EKS Scout as one part of a comprehensive security assessment process.

# Scan and output findings to a specific JSON file
python eks_scout.py --cluster-name staging-cluster --region ap-southeast-2 -o staging_findings.json -f json

# Run with debug logging
python eks_scout.py --cluster-name test-cluster --region us-west-2 --debug
