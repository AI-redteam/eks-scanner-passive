# EKS Scout - Finding Validation Guide

This guide provides commands and steps to manually validate the findings reported by the EKS Scout tool. For each finding, use the "Affected Components" details from the scanner's output to fill in the placeholders in the validation commands.

## Table of Contents

1.  [EKS Cluster Configuration](#1-eks-cluster-configuration)
    * [EKS Public API Endpoint Open to Internet](#eks-public-api-endpoint-open-to-internet)
    * [EKS Public API Endpoint Access Enabled](#eks-public-api-endpoint-access-enabled)
    * [EKS API Endpoint Access Disabled](#eks-api-endpoint-access-disabled)
    * [EKS Private API Endpoint Access Disabled](#eks-private-api-endpoint-access-disabled)
    * [EKS Control Plane Logging Disabled](#eks-control-plane-logging-disabled)
    * [EKS Secrets Encryption Not Enabled](#eks-secrets-encryption-not-enabled)
    * [EKS Secrets Resource Not Explicitly Encrypted](#eks-secrets-resource-not-explicitly-encrypted)
2.  [EKS Nodegroup Configuration](#2-eks-nodegroup-configuration)
    * [Nodegroup SSH Access Enabled Without Source Restriction](#nodegroup-ssh-access-enabled-without-source-restriction)
    * [Nodegroup SSH Access Enabled](#nodegroup-ssh-access-enabled)
3.  [Kubernetes Namespace Security](#3-kubernetes-namespace-security)
    * [PSA Label Missing](#psa-label-missing)
    * [PSA Label Too Permissive](#psa-label-too-permissive)
    * [Namespace Lacks ResourceQuota](#namespace-lacks-resourcequota)
    * [Namespace Lacks LimitRange](#namespace-lacks-limitrange)
4.  [Kubernetes Pod & Container Security](#4-kubernetes-pod--container-security)
    * [Pod IRSA Role Potentially Overly Permissive](#pod-irsa-role-potentially-overly-permissive)
    * [Pod Using Host Network](#pod-using-host-network)
    * [Pod Using Host PID Namespace](#pod-using-host-pid-namespace)
    * [Pod Using Host IPC Namespace](#pod-using-host-ipc-namespace)
    * [Pod Using HostPath Volume](#pod-using-hostpath-volume)
    * [Privileged Container](#privileged-container)
    * [Container Running As Root](#container-running-as-root)
    * [Container Allowed to Run As Root](#container-allowed-to-run-as-root)
    * [Container May Run As Root](#container-may-run-as-root)
    * [Container Missing Resource Limits](#container-missing-resource-limits)
    * [Container Allows Privilege Escalation](#container-allows-privilege-escalation)
    * [Container Root Filesystem Writable](#container-root-filesystem-writable)
    * [Image Uses Latest Tag](#image-uses-latest-tag)
    * [Image From Potentially Unapproved Registry](#image-from-potentially-unapproved-registry)
5.  [Kubernetes Service Accounts](#5-kubernetes-service-accounts)
    * [Service Account IRSA Role Potentially Overly Permissive](#service-account-irsa-role-potentially-overly-permissive)
    * [Service Account Token Automount Enabled](#service-account-token-automount-enabled)
    * [Default Service Account Allows Token Automount](#default-service-account-allows-token-automount)
6.  [Kubernetes RBAC](#6-kubernetes-rbac)
    * [ClusterRoleBinding Grants High Privileges](#clusterrolebinding-grants-high-privileges)
    * [ClusterRoleBinding to Sensitive Subject](#clusterrolebinding-to-sensitive-subject)
    * [RoleBinding Grants Cluster Admin](#rolebinding-grants-cluster-admin)
    * [RoleBinding Grants High Privileges in Namespace](#rolebinding-grants-high-privileges-in-namespace)
    * [RoleBinding Involves Default Service Account](#rolebinding-involves-default-service-account)
    * [Role Contains Risky Permissions](#role-contains-risky-permissions)
7.  [Kubernetes Network Policies](#7-kubernetes-network-policies)
    * [Namespace Lacks Network Policy](#namespace-lacks-network-policy)
    * [Network Policy Allows All Ingress Sources](#network-policy-allows-all-ingress-sources)
    * [Network Policy Allows Ingress From All Pods](#network-policy-allows-ingress-from-all-pods)
    * [Network Policy Allows Ingress From All Namespaces](#network-policy-allows-ingress-from-all-namespaces)
    * [Network Policy Allows Ingress From Any IP](#network-policy-allows-ingress-from-any-ip)
8.  [Kubernetes Network Exposure](#8-kubernetes-network-exposure)
    * [Service Exposed via LoadBalancer](#service-exposed-via-loadbalancer)
    * [Ingress Uses Default Backend](#ingress-uses-default-backend)
    * [Ingress Rule Uses Wildcard Host](#ingress-rule-uses-wildcard-host)
    * [Ingress Rule Lacks TLS Configuration](#ingress-rule-lacks-tls-configuration)
9.  [Kubernetes Configuration & Secrets](#9-kubernetes-configuration--secrets)
    * [Potential Sensitive Data in ConfigMap Keys](#potential-sensitive-data-in-configmap-keys)

---

## 1. EKS Cluster Configuration

### EKS Public API Endpoint Open to Internet
* **Description:** The EKS cluster's Kubernetes API server endpoint is publicly accessible and not restricted to specific IP CIDR blocks, or is open to `0.0.0.0/0`.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.resourcesVpcConfig.{EndpointPublicAccess:endpointPublicAccess, PublicAccessCidrs:publicAccessCidrs}"
    ```
* **What to Look For:** Confirm `EndpointPublicAccess` is `true` and `PublicAccessCidrs` includes `0.0.0.0/0` or is an empty list (which defaults to all IPs).

### EKS Public API Endpoint Access Enabled
* **Description:** The EKS cluster's Kubernetes API server endpoint is publicly accessible but may be restricted by specific CIDR blocks.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.resourcesVpcConfig.{EndpointPublicAccess:endpointPublicAccess, PublicAccessCidrs:publicAccessCidrs}"
    ```
* **What to Look For:** Confirm `EndpointPublicAccess` is `true` and `PublicAccessCidrs` contains a list of specific IP ranges (not `0.0.0.0/0`).

### EKS API Endpoint Access Disabled
* **Description:** Both public and private access to the EKS cluster's API endpoint are disabled. This usually indicates a misconfiguration.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.resourcesVpcConfig.{EndpointPublicAccess:endpointPublicAccess, EndpointPrivateAccess:endpointPrivateAccess}"
    ```
* **What to Look For:** Confirm both `EndpointPublicAccess` and `EndpointPrivateAccess` are `false`.

### EKS Private API Endpoint Access Disabled
* **Description:** Private access to the EKS cluster's API endpoint is disabled, relying solely on public access.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.resourcesVpcConfig.endpointPrivateAccess"
    ```
* **What to Look For:** Confirm the output is `false`.

### EKS Control Plane Logging Disabled
* **Description:** One or more recommended control plane log types (api, audit, authenticator, controllerManager, scheduler) are not enabled.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.logging.clusterLogging"
    ```
* **What to Look For:** Review the output. For each required log type, check if an entry exists with `enabled: true`. If any type is missing or has `enabled: false`, the finding is confirmed.

### EKS Secrets Encryption Not Enabled
* **Description:** Envelope encryption for Kubernetes secrets using a KMS key is not configured for the cluster.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.encryptionConfig"
    ```
* **What to Look For:** The output is `null`, an empty list `[]`, or the list does not contain a provider with a `keyArn`.

### EKS Secrets Resource Not Explicitly Encrypted
* **Description:** Envelope encryption is configured with a KMS key, but the `secrets` resource type is not explicitly included in the list of resources to be encrypted.
* **Validation Command:**
    ```bash
    aws eks describe-cluster --name <cluster_name> --region <region> --query "cluster.encryptionConfig"
    ```
* **What to Look For:** Inspect each object in the `encryptionConfig` array. Verify that at least one object which has a `provider.keyArn` also includes `"secrets"` in its `resources` array.

## 2. EKS Nodegroup Configuration

### Nodegroup SSH Access Enabled Without Source Restriction
* **Description:** SSH access is enabled for a nodegroup, but it's not restricted to specific source Security Groups, potentially allowing access from any IP with the key.
* **Validation Command:**
    ```bash
    aws eks describe-nodegroup --cluster-name <cluster_name> --nodegroup-name <nodegroup_name> --region <region> --query "nodegroup.remoteAccess"
    ```
* **What to Look For:** Confirm `ec2SshKey` has a value (SSH key name) and `sourceSecurityGroups` is `null` or an empty list `[]`.

### Nodegroup SSH Access Enabled
* **Description:** SSH access is enabled for a nodegroup and is restricted by source Security Groups.
* **Validation Command:**
    ```bash
    aws eks describe-nodegroup --cluster-name <cluster_name> --nodegroup-name <nodegroup_name> --region <region> --query "nodegroup.remoteAccess"
    ```
* **What to Look For:** Confirm `ec2SshKey` has a value and `sourceSecurityGroups` contains a list of Security Group IDs. Review these SGs separately to ensure they are adequately restricted.

## 3. Kubernetes Namespace Security

### PSA Label Missing
* **Description:** A namespace does not have the `pod-security.kubernetes.io/enforce` label for Pod Security Admission.
* **Validation Command:**
    ```bash
    kubectl get namespace <namespace_name> -o yaml
    ```
* **What to Look For:** In the `metadata.labels` section, confirm the absence of the `pod-security.kubernetes.io/enforce` label.

### PSA Label Too Permissive
* **Description:** A namespace has a PSA `enforce` label, but its value is too permissive (e.g., `privileged` when `baseline` or `restricted` is expected).
* **Validation Command:**
    ```bash
    kubectl get namespace <namespace_name> -o yaml
    ```
* **What to Look For:** In the `metadata.labels` section, inspect the value of `pod-security.kubernetes.io/enforce`. Confirm it is set to a less secure level than desired (e.g., `privileged`).

### Namespace Lacks ResourceQuota
* **Description:** A namespace does not have any `ResourceQuota` objects defined.
* **Validation Command:**
    ```bash
    kubectl get resourcequota -n <namespace_name>
    ```
* **What to Look For:** The command returns "No resources found" or an empty list.

### Namespace Lacks LimitRange
* **Description:** A namespace does not have any `LimitRange` objects defined.
* **Validation Command:**
    ```bash
    kubectl get limitrange -n <namespace_name>
    ```
* **What to Look For:** The command returns "No resources found" or an empty list.

## 4. Kubernetes Pod & Container Security

### Pod IRSA Role Potentially Overly Permissive
* **Description:** A Pod's IRSA annotation points to an IAM role ARN that contains keywords like "admin" or "*", suggesting it might be overly permissive. This requires manual IAM policy review.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `metadata.annotations`, find `eks.amazonaws.com/role-arn`. Note the ARN. Then, use AWS CLI to inspect the role's policies:
    ```bash
    aws iam list-attached-role-policies --role-name <role_name_from_arn>
    aws iam list-role-policies --role-name <role_name_from_arn> # For inline policies
    # Further describe specific policies if needed
    ```

### Pod Using Host Network
* **Description:** A pod is configured to use the host's network namespace.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In the `spec` section, confirm `hostNetwork: true`.

### Pod Using Host PID Namespace
* **Description:** A pod is configured to use the host's PID namespace.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In the `spec` section, confirm `hostPID: true`.

### Pod Using Host IPC Namespace
* **Description:** A pod is configured to use the host's IPC namespace.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In the `spec` section, confirm `hostIPC: true`.

### Pod Using HostPath Volume
* **Description:** A pod mounts a volume using `hostPath`, directly accessing the underlying node's filesystem.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.volumes`, look for an entry that has a `hostPath` field. Note the `path` specified.

### Privileged Container
* **Description:** A container within a pod is running in privileged mode.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `securityContext` for `privileged: true`.

### Container Running As Root
* **Description:** A container is explicitly configured to run as UID 0.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `securityContext` for `runAsUser: 0`. Also check the pod-level `spec.securityContext`.

### Container Allowed to Run As Root
* **Description:** A container is explicitly allowed to run as root (`runAsNonRoot: false`).
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `securityContext` for `runAsNonRoot: false`. Also check the pod-level `spec.securityContext`.

### Container May Run As Root
* **Description:** A container does not have `runAsNonRoot: true` or a specific `runAsUser` defined, meaning it might run as root depending on the image's default user.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `securityContext`. Confirm that `runAsNonRoot` is not `true` AND `runAsUser` is not set to a non-zero value. Also check the pod-level `spec.securityContext`.

### Container Missing Resource Limits
* **Description:** A container does not have CPU and/or memory limits defined.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `resources.limits`. Confirm that `cpu` or `memory` (or both) are missing.

### Container Allows Privilege Escalation
* **Description:** A container's security context does not explicitly set `allowPrivilegeEscalation: false`.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `securityContext`. Confirm `allowPrivilegeEscalation` is either `true` or not present (defaults to true). Also check pod-level `spec.securityContext`.

### Container Root Filesystem Writable
* **Description:** A container's root filesystem is not set to read-only.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and check its `securityContext`. Confirm `readOnlyRootFilesystem` is either `false` or not present (defaults to false). Also check pod-level `spec.securityContext`.

### Image Uses Latest Tag
* **Description:** A container is using an image with the `:latest` tag or no tag.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and inspect its `image` field. Confirm it ends with `:latest` or has no tag specified after the image name.

### Image From Potentially Unapproved Registry
* **Description:** A container image is sourced from a registry not in a predefined list of common/approved registries.
* **Validation Command:**
    ```bash
    kubectl get pod <pod_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.containers[]` (or `spec.initContainers[]`), find the specific `<container_name>` and inspect its `image` field. Note the registry part (e.g., `myregistry.com/...` or infer `docker.io` if no registry is specified). Compare against your organization's approved registries.

## 5. Kubernetes Service Accounts

### Service Account IRSA Role Potentially Overly Permissive
* **Description:** A ServiceAccount's IRSA annotation points to an IAM role ARN that contains keywords like "admin" or "*".
* **Validation Command:**
    ```bash
    kubectl get serviceaccount <sa_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `metadata.annotations`, find `eks.amazonaws.com/role-arn`. Note the ARN. Then, use AWS CLI to inspect the role's policies (see "Pod IRSA Role..." for AWS commands).

### Service Account Token Automount Enabled
* **Description:** A non-default ServiceAccount has `automountServiceAccountToken: true` or it's not set (defaults to true).
* **Validation Command:**
    ```bash
    kubectl get serviceaccount <sa_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Confirm `automountServiceAccountToken` is `true` or absent. Ensure `<sa_name>` is not `default`.

### Default Service Account Allows Token Automount
* **Description:** The `default` ServiceAccount in a namespace has `automountServiceAccountToken: true` or it's not set.
* **Validation Command:**
    ```bash
    kubectl get serviceaccount default -n <namespace_name> -o yaml
    ```
* **What to Look For:** Confirm `automountServiceAccountToken` is `true` or absent.

## 6. Kubernetes RBAC

### ClusterRoleBinding Grants High Privileges
* **Description:** A `ClusterRoleBinding` grants a highly privileged role (like `cluster-admin`) to a subject.
* **Validation Command:**
    ```bash
    kubectl get clusterrolebinding <binding_name> -o yaml
    ```
* **What to Look For:** Inspect `roleRef.name` (e.g., `cluster-admin`) and the `subjects` list.

### ClusterRoleBinding to Sensitive Subject
* **Description:** A `ClusterRoleBinding` assigns permissions to a sensitive system group (e.g., `system:unauthenticated`) or the default service account in `kube-system`.
* **Validation Command:**
    ```bash
    kubectl get clusterrolebinding <binding_name> -o yaml
    ```
* **What to Look For:** Inspect the `subjects` list for entries like `kind: Group, name: system:unauthenticated` or `kind: ServiceAccount, name: default, namespace: kube-system`.

### RoleBinding Grants Cluster Admin
* **Description:** A `RoleBinding` (namespace-scoped) incorrectly attempts to bind `cluster-admin` (a ClusterRole) to a subject within a namespace.
* **Validation Command:**
    ```bash
    kubectl get rolebinding <binding_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Inspect `roleRef.kind` (should be `ClusterRole`) and `roleRef.name` (should be `cluster-admin`).

### RoleBinding Grants High Privileges in Namespace
* **Description:** A `RoleBinding` grants a highly privileged namespace-scoped role (like `admin` or `edit`) to a subject.
* **Validation Command:**
    ```bash
    kubectl get rolebinding <binding_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Inspect `roleRef.name` (e.g., `admin`, `edit`) and the `subjects` list.

### RoleBinding Involves Default Service Account
* **Description:** A `RoleBinding` grants permissions to the `default` ServiceAccount in a namespace.
* **Validation Command:**
    ```bash
    kubectl get rolebinding <binding_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In the `subjects` list, look for an entry with `kind: ServiceAccount` and `name: default`.

### Role Contains Risky Permissions
* **Description:** A `Role` or `ClusterRole` definition includes overly permissive rules (wildcards, sensitive verbs/resources).
* **Validation Command (for Role):**
    ```bash
    kubectl get role <role_name> -n <namespace_name> -o yaml
    ```
* **Validation Command (for ClusterRole):**
    ```bash
    kubectl get clusterrole <role_name> -o yaml
    ```
* **What to Look For:** Inspect the `rules` array. Look for `verbs: ["*"]`, `resources: ["*"]`, `apiGroups: ["*"]`, or combinations of sensitive verbs (like `create`, `delete`, `patch`, `impersonate`, `bind`, `escalate`, `pods/exec`) on sensitive resources (like `secrets`, `pods`, `serviceaccounts`, other RBAC objects).

## 7. Kubernetes Network Policies

### Namespace Lacks Network Policy
* **Description:** A namespace does not have any `NetworkPolicy` objects defined, allowing all pod-to-pod traffic by default.
* **Validation Command:**
    ```bash
    kubectl get networkpolicy -n <namespace_name>
    ```
* **What to Look For:** The command returns "No resources found" or an empty list.

### Network Policy Allows All Ingress Sources
* **Description:** A `NetworkPolicy` has an ingress rule that allows traffic from all sources (e.g., empty `from` clause).
* **Validation Command:**
    ```bash
    kubectl get networkpolicy <policy_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.ingress[]`, find a rule where the `from` field is absent or an empty list `[]`.

### Network Policy Allows Ingress From All Pods
* **Description:** A `NetworkPolicy` has an ingress rule allowing traffic from all pods in selected namespaces (empty `podSelector: {}`).
* **Validation Command:**
    ```bash
    kubectl get networkpolicy <policy_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.ingress[].from[]`, look for an entry with `podSelector: {}` (an empty object).

### Network Policy Allows Ingress From All Namespaces
* **Description:** A `NetworkPolicy` has an ingress rule allowing traffic from all namespaces (empty `namespaceSelector: {}`).
* **Validation Command:**
    ```bash
    kubectl get networkpolicy <policy_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.ingress[].from[]`, look for an entry with `namespaceSelector: {}` (an empty object).

### Network Policy Allows Ingress From Any IP
* **Description:** A `NetworkPolicy` has an ingress rule allowing traffic from `0.0.0.0/0`.
* **Validation Command:**
    ```bash
    kubectl get networkpolicy <policy_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.ingress[].from[]`, look for an entry with `ipBlock.cidr: "0.0.0.0/0"`.

## 8. Kubernetes Network Exposure

### Service Exposed via LoadBalancer
* **Description:** A Kubernetes `Service` is of `Type: LoadBalancer`, provisioning an external cloud load balancer.
* **Validation Command:**
    ```bash
    kubectl get service <service_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.type`, confirm the value is `LoadBalancer`. Note `status.loadBalancer.ingress[].hostname` or `ip` for the external endpoint.

### Ingress Uses Default Backend
* **Description:** An `Ingress` resource defines a `defaultBackend` but has no specific rules, routing all unmatched traffic to it.
* **Validation Command:**
    ```bash
    kubectl get ingress <ingress_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Confirm `spec.defaultBackend` is defined and `spec.rules` is absent or empty.

### Ingress Rule Uses Wildcard Host
* **Description:** An `Ingress` rule uses a wildcard `*` for the host.
* **Validation Command:**
    ```bash
    kubectl get ingress <ingress_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** In `spec.rules[]`, look for an entry where `host: "*"`.

### Ingress Rule Lacks TLS Configuration
* **Description:** An `Ingress` rule defines a specific host, but this host is not covered by any entry in `spec.tls`.
* **Validation Command:**
    ```bash
    kubectl get ingress <ingress_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Identify all hosts listed in `spec.rules[].host`. Then check the `spec.tls` array. For each `tls` entry, look at its `hosts` list. If a host from `spec.rules` is not found in any of the `spec.tls[].hosts` lists, the finding is confirmed for that host.

## 9. Kubernetes Configuration & Secrets

### Potential Sensitive Data in ConfigMap Keys
* **Description:** A `ConfigMap` contains data keys with names suggesting sensitive content (e.g., "password", "token").
* **Validation Command:**
    ```bash
    kubectl get configmap <configmap_name> -n <namespace_name> -o yaml
    ```
* **What to Look For:** Inspect the keys under the `data` field. Check if any key names match patterns like "password", "secret", "token", "apikey", etc. *This finding requires further manual review of the actual data values if possible and permitted, as key names can be misleading.*

---
This guide should provide a solid starting point for validating the findings from EKS Scout.
