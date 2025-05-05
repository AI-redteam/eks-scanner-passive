#!/usr/bin/env python3

import subprocess
import json
import csv
from datetime import datetime

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

def run_cmd(cmd):
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
if result.returncode != 0:
return None
return result.stdout

def get_namespaces():
output = run_cmd("kubectl get namespaces -o json")
if not output:
return []
namespaces = json.loads(output)['items']
return [ns['metadata']['name'] for ns in namespaces]

def get_pods(namespace):
output = run_cmd(f"kubectl get pods -n {namespace} -o json")
if not output:
return []
pods = json.loads(output)['items']
return pods

def get_serviceaccounts(namespace):
output = run_cmd(f"kubectl get serviceaccounts -n {namespace} -o json")
if not output:
return []
sas = json.loads(output)['items']
return sas

def get_rolebindings(namespace):
output = run_cmd(f"kubectl get rolebindings -n {namespace} -o json")
if not output:
return []
return json.loads(output)['items']

def get_network_policies(namespace):
output = run_cmd(f"kubectl get networkpolicy -n {namespace} -o json")
if not output:
return []
return json.loads(output)['items']

def analyze_pod(pod, namespace):
findings = []
metadata = pod.get('metadata', {})
spec = pod.get('spec', {})
annotations = metadata.get('annotations', {})
iam_role = annotations.get('eks.amazonaws.com/role-arn')

if iam_role and ("admin" in iam_role.lower() or "*" in iam_role):
findings.append({
'severity': SEVERITY_HIGH,
'type': 'IAM Role Overly Permissive',
'namespace': namespace,
'name': metadata['name'],
'details': f'Role allows potential admin or wildcard permissions: {iam_role}',
'recommendation': 'Limit IAM role permissions according to least privilege principle.',
'reference': 'CIS 5.1.5'
})

if spec.get('hostNetwork', False):
findings.append({
'severity': SEVERITY_HIGH,
'type': 'Host Network Enabled',
'namespace': namespace,
'name': metadata['name'],
'details': 'Pod is configured with hostNetwork: true.',
'recommendation': 'Avoid using hostNetwork unless absolutely necessary.',
'reference': 'CIS 5.2.2'
})

if spec.get('volumes'):
for volume in spec['volumes']:
if 'hostPath' in volume:
findings.append({
'severity': SEVERITY_HIGH,
'type': 'HostPath Volume Used',
'namespace': namespace,
'name': metadata['name'],
'details': f'Pod uses hostPath volume: {volume["hostPath"].get("path")}',
'recommendation': 'Avoid using hostPath volumes due to host compromise risk.',
'reference': 'CIS 5.2.5'
})

security_context = spec.get('securityContext', {})
if not security_context.get('runAsNonRoot', False):
findings.append({
'severity': SEVERITY_MEDIUM,
'type': 'Pod Missing Security Context',
'namespace': namespace,
'name': metadata['name'],
'details': 'Pod is running containers as root.',
'recommendation': 'Enforce runAsNonRoot in security context.',
'reference': 'CIS 5.2.3'
})

containers = spec.get('containers', [])
for container in containers:
resources = container.get('resources', {})
limits = resources.get('limits')
if not limits:
findings.append({
'severity': SEVERITY_LOW,
'type': 'Pod Without Resource Limits',
'namespace': namespace,
'name': metadata['name'],
'details': f'Container {container.get("name")} has no CPU/memory resource limits.',
'recommendation': 'Set CPU and memory resource limits.',
'reference': 'CIS 5.2.4'
})

sc = container.get('securityContext', {})
if sc.get('privileged', False):
findings.append({
'severity': SEVERITY_HIGH,
'type': 'Privileged Container',
'namespace': namespace,
'name': metadata['name'],
'details': f'Container {container.get("name")} is running in privileged mode.',
'recommendation': 'Avoid privileged containers unless absolutely necessary.',
'reference': 'CIS 5.2.1'
})

return findings

def analyze_serviceaccount(sa, namespace):
findings = []
metadata = sa['metadata']
annotations = metadata.get('annotations', {})
iam_role = annotations.get('eks.amazonaws.com/role-arn')

if iam_role and ("admin" in iam_role.lower() or "*" in iam_role):
findings.append({
'severity': SEVERITY_HIGH,
'type': 'IAM Role Overly Permissive',
'namespace': namespace,
'name': metadata['name'],
'details': f'ServiceAccount IAM role allows potential admin or wildcard permissions: {iam_role}',
'recommendation': 'Limit IAM role permissions according to least privilege principle.',
'reference': 'CIS 5.1.5'
})

if metadata['name'] == 'default':
findings.append({
'severity': SEVERITY_MEDIUM,
'type': 'Default Service Account in Use',
'namespace': namespace,
'name': metadata['name'],
'details': 'Default service account is actively in use.',
'recommendation': 'Create dedicated service accounts with limited roles.',
'reference': 'CIS 5.1.6'
})

if sa.get('automountServiceAccountToken', True):
findings.append({
'severity': SEVERITY_MEDIUM,
'type': 'Token Automount Enabled',
'namespace': namespace,
'name': metadata['name'],
'details': 'automountServiceAccountToken is enabled, which may expose the token unnecessarily.',
'recommendation': 'Disable automountServiceAccountToken unless explicitly required.',
'reference': 'CIS 5.1.7'
})

return findings

def analyze_rolebindings(rb, namespace):
findings = []
subjects = rb.get('subjects', [])
role_ref = rb.get('roleRef', {}).get('name', '')
for subject in subjects:
if role_ref == 'cluster-admin':
findings.append({
'severity': SEVERITY_HIGH,
'type': 'Overly Permissive RBAC Binding',
'namespace': namespace,
'name': subject.get('name'),
'details': f'RoleBinding grants cluster-admin privileges to {subject.get("kind")}/{subject.get("name")}.',
'recommendation': 'Avoid assigning cluster-admin roles; use scoped roles with least privilege.',
'reference': 'CIS 5.1.1'
})
return findings

def analyze_network_policy(namespace):
findings = []
policies = get_network_policies(namespace)
if not policies:
findings.append({
'severity': SEVERITY_MEDIUM,
'type': 'No Network Policy Defined',
'namespace': namespace,
'name': namespace,
'details': 'Namespace has no network policy defined, allowing unrestricted network traffic between pods.',
'recommendation': 'Define network policies to restrict pod communication.',
'reference': 'CIS 5.3.2'
})
return findings

def export_findings_to_csv(findings, filename="eks_findings_plextrac.csv"):
fieldnames = [
"Title", "Description", "Recommendation", "Severity",
"Affected Asset", "References", "Tags", "Status"
]
with open(filename, mode='w', newline='') as csvfile:
writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
writer.writeheader()
for finding in findings:
writer.writerow({
"Title": finding['type'],
"Description": finding['details'],
"Recommendation": finding['recommendation'],
"Severity": finding['severity'],
"Affected Asset": f"{finding['namespace']}/{finding['name']}",
"References": finding['reference'],
"Tags": "EKS,Kubernetes,Security", # Static tags for now
"Status": "Open"
})
print(f"Exported findings to {filename}")

def main():
all_findings = []

print("Starting AWS EKS Kubernetes Security Scanner...")

namespaces = get_namespaces()
if not namespaces:
print("No namespaces found or error connecting to cluster.")
return

for ns in namespaces:
pods = get_pods(ns)
sas = get_serviceaccounts(ns)
rbs = get_rolebindings(ns)

all_findings.extend(analyze_network_policy(ns))

for pod in pods:
findings = analyze_pod(pod, ns)
all_findings.extend(findings)

for sa in sas:
findings = analyze_serviceaccount(sa, ns)
all_findings.extend(findings)

for rb in rbs:
findings = analyze_rolebindings(rb, ns)
all_findings.extend(findings)

if all_findings:
print("\nSecurity Findings:")
for finding in all_findings:
print(f"- [{finding['severity']}] {finding['type']}: {finding['namespace']}/{finding['name']}")
print(f" Details: {finding['details']}")
print(f" Recommendation: {finding['recommendation']}")
print(f" Reference: {finding['reference']}\n")
export_findings_to_csv(all_findings)
else:
print("No significant security issues found in the cluster.")

if __name__ == "__main__":
main()
