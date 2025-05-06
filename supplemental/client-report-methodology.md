# AWS EKS Security Configuration Review Methodology

## 1. Introduction

This document outlines the comprehensive methodology employed to assess the security posture of the AWS Elastic Kubernetes Service (EKS) environment. The review involved a detailed examination of the Kubernetes cluster configuration, its interaction with AWS services, and the security settings of deployed workloads. This was achieved through systematic interrogation of the Kubernetes API using `kubectl` commands and querying AWS service configurations via the AWS Command Line Interface (CLI), followed by careful analysis of the gathered data.

The primary objective was to identify security misconfigurations, deviations from established best practices, and potential vulnerabilities that could expose the environment to risk. The assessment encompassed the following key areas.

## 2. Detailed Methodology

### 2.1. EKS Cluster-Level Configuration Analysis

A thorough inspection of the core EKS cluster settings was performed. This involved:

* **API Server Endpoint Security:** The accessibility of the Kubernetes API server endpoint was carefully evaluated, including whether it was publicly exposed or restricted to private VPC access. For public endpoints, the configured IP address whitelisting (CIDR restrictions) was scrutinized.
* **Control Plane Logging:** The status of critical control plane logging (api, audit, authenticator, controllerManager, scheduler) was verified to ensure comprehensive audit trails are captured for security monitoring and incident response.
* **Secrets Encryption:** The configuration for envelope encryption of Kubernetes Secrets using AWS Key Management Service (KMS) was examined to confirm that sensitive data stored in `etcd` is appropriately protected at rest.

### 2.2. EKS Nodegroup and Worker Node Security

The configuration of EKS nodegroups was reviewed to ensure worker nodes adhere to security best practices:

* **Remote Access Controls:** Settings related to SSH access to worker nodes were inspected, including the assignment of EC2 SSH keys and the use of source security groups to restrict access to authorized administrative networks.
* **Node IAM Role Scrutiny:** The IAM roles assigned to worker nodegroups were identified. While a full IAM policy analysis is a separate activity, these roles were noted to understand the permissions granted to nodes for interacting with other AWS services.
* **Instance Metadata Service (IMDSv2):** Configurations related to IMDSv2 enforcement (e.g., via Launch Templates) were reviewed where possible to protect against potential Server-Side Request Forgery (SSRF) vulnerabilities.

### 2.3. Kubernetes Namespace Security and Governance

Each namespace within the cluster (excluding default system namespaces for certain checks) was methodically reviewed for security and resource governance controls:

* **Pod Security Admission (PSA):** Namespace labels were inspected to verify the application and enforcement level (e.g., `baseline`, `restricted`) of Pod Security Admission standards, which dictate baseline security requirements for pods.
* **Resource Quotas and Limit Ranges:** The presence of `ResourceQuota` objects (to cap overall resource consumption) and `LimitRange` objects (to define default container resource requests/limits) was checked in each namespace to prevent resource exhaustion and ensure workload stability.

### 2.4. Pod and Container Security Hardening

A granular analysis of pod specifications across all relevant namespaces was undertaken. This involved manually retrieving and inspecting the YAML definitions of individual pods to identify insecure configurations within container settings:

* **Host Namespace & Path Risks:** Pods were examined for the use of sensitive host namespaces (`hostNetwork`, `hostPID`, `hostIPC`) and `hostPath` volume mounts that could grant excessive access to the underlying node.
* **Privilege Levels:** Containers were checked for privileged mode (`securityContext.privileged: true`), which grants unrestricted host access.
* **User Context:** The effective user ID of containers was assessed, specifically identifying containers running as root or those not explicitly configured to run as non-root users (`runAsNonRoot`).
* **Privilege Escalation:** Configurations allowing privilege escalation within containers (`allowPrivilegeEscalation: true`) were identified.
* **Filesystem Security:** The root filesystem mount status was checked for containers not configured with a `readOnlyRootFilesystem`.
* **Resource Management:** Containers were inspected for the absence of CPU and memory resource limits, which can lead to resource contention.
* **Image Provenance:** Container image specifications were reviewed for the use of mutable tags like `:latest` and for images potentially sourced from unverified or non-standard registries.
* **Service Account Linkage:** The `serviceAccountName` assigned to each pod, and any AWS IAM role ARNs associated via IRSA annotations, were noted for cross-referencing during RBAC and IAM permission reviews.

### 2.5. Service Account Configuration Review

Service accounts in each namespace were examined, focusing on:

* **IAM Roles for Service Accounts (IRSA):** Annotations linking Kubernetes service accounts to AWS IAM roles were identified for subsequent IAM policy review.
* **Token Automounting:** The `automountServiceAccountToken` setting was checked, particularly for the `default` service account and other potentially widely used accounts, to minimize unnecessary exposure of API credentials to pods.

### 2.6. RBAC (Role-Based Access Control) Posture Assessment

A comprehensive review of Kubernetes RBAC settings was conducted by manually querying and analyzing all `Roles`, `ClusterRoles`, `RoleBindings`, and `ClusterRoleBindings`:

* **Highly Privileged Bindings:** Bindings granting `cluster-admin` or broad administrative roles (e.g., namespace `admin`, `edit`) to users, groups, or service accounts were identified and scrutinized.
* **Overly Permissive Role Definitions:** Role and ClusterRole definitions were inspected for rules containing wildcards (`*`) for verbs, resources, or API groups, or granting high-risk permissions such as `pod/exec`, `secrets/*`, or `impersonate`.
* **Sensitive Subject Bindings:** Bindings to sensitive system principals like `system:unauthenticated`, `system:authenticated`, or default service accounts in critical namespaces were carefully evaluated.

### 2.7. Network Segmentation and Policies

The implementation and effectiveness of network segmentation were evaluated through an inspection of `NetworkPolicy` resources:

* **Default Network Stance:** Namespaces lacking any NetworkPolicies were identified, as this typically allows unrestricted pod-to-pod communication.
* **Permissive Policy Rules:** Existing NetworkPolicies were reviewed for rules that might permit overly broad ingress or egress, such as allowing traffic from all pods, all namespaces, or from unrestricted IP CIDRs (e.g., `0.0.0.0/0`).

### 2.8. Network Exposure of Services

The mechanisms by which applications are exposed both internally and externally were carefully examined:

* **Externally Exposed Services:** Kubernetes `Service` objects of `Type: LoadBalancer` were identified, as these result in the provisioning of external cloud load balancers.
* **Ingress Configuration:** `Ingress` resources were analyzed for secure configuration, including verifying that rules exposing applications over HTTP have corresponding TLS configurations to enforce HTTPS, and checking for the use of wildcard hosts (`*`) which can introduce routing ambiguities.

### 2.9. Configuration and Secret Management Practices (Baseline Check)

A baseline review of how configuration data and secrets are managed was performed:

* **ConfigMap Data Scrutiny:** Keys within `ConfigMap` objects were inspected for common patterns (e.g., "password", "token", "key") that might indicate the insecure storage of sensitive information.
* **Secret Object Identification:** `Secret` objects were identified by their type (e.g., `kubernetes.io/tls`, `kubernetes.io/dockerconfigjson`) to understand their intended purpose, noting them for review of associated access controls via RBAC.

## 3. Conclusion

This multi-faceted approach, involving detailed manual queries and careful analysis of the resulting data from both the AWS and Kubernetes control planes, aimed to provide a comprehensive understanding of the EKS environment's security configuration and identify areas for improvement.
