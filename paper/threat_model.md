# Threat Model

## Attacker Goal

Obtain AWS IAM AdministratorAccess or equivalent high-privilege role
session credentials from within a Kubernetes cluster that uses IAM
Roles for Service Accounts (IRSA) for workload identity federation.

## Attacker Entry Point

The attacker has achieved code execution inside a Kubernetes pod. This
is a realistic, well-documented initial access primitive achieved via:
- Exploitation of a vulnerability in a containerized application
- Supply chain compromise of a container image
- Misconfigured container security context (e.g. privileged pod,
  hostPath mount) exploited via another vulnerability
- Compromised CI/CD pipeline deploying attacker-controlled code

The attacker does NOT need to compromise the Kubernetes control plane
itself, escape the container runtime, or have direct network access to
the Kubernetes API server.

## Attacker Capabilities

The attacker CAN:
- Read the pod's service account token from
  /var/run/secrets/kubernetes.io/serviceaccount/token
- Read the pod's namespace and service account name from the
  Kubernetes downward API or environment variables
- Make outbound HTTPS requests to the AWS STS regional endpoint
  (sts.amazonaws.com or regional equivalent)
- Use the service account token with AWS STS
  AssumeRoleWithWebIdentity to obtain temporary credentials for the
  IRSA-mapped IAM role, if one is configured
- Use those temporary credentials to call AWS IAM and service APIs
  within the permissions granted to the assumed role

The attacker CANNOT (within this threat model):
- Directly compromise the Kubernetes API server (kube-apiserver)
  or etcd
- Escape the container runtime to the underlying node
- Intercept or forge the OIDC token signing process
- Modify IAM policies, trust policies, or RBAC bindings (these are
  the configurations our tool reads; the attacker can only use
  existing permissions, not change them)
- Access other pods' service account tokens without additional
  intra-cluster privilege escalation steps (modeled separately)

## IRSA Assumption

The target cluster uses EKS-compatible IRSA: the cluster has an OIDC
identity provider configured, at least one ServiceAccount has the
eks.amazonaws.com/role-arn annotation set to a valid IAM role ARN,
and AWS STS is reachable from within the cluster network. This is the
standard, recommended configuration for workload identity on EKS and
is enabled by default on AWS EKS clusters.

## What "Escalation" Means in This Model

An escalation path is a sequence of AWS IAM and/or Kubernetes RBAC
permission grants that, taken together, allow an attacker who starts
with code execution in a pod to obtain credentials for an AWS IAM
role with AdministratorAccess or equivalent (Action: "*" on
Resource: "*"). The path must be achievable using only the permissions
that already exist in the current configuration -- no CVE exploitation,
no brute-forcing, no social engineering.

An escalation path is considered cross-layer (and therefore novel
within our tool's scope) if it requires traversing at least one
Kubernetes RBAC entity (ServiceAccount, Role, or ClusterRole) AND at
least one AWS IAM entity (User, Role, or Group) -- i.e. it cannot be
detected by analyzing either layer in isolation.

## Out of Scope

The following are explicitly outside this threat model:
- Network-level attacks (firewall bypass, traffic interception)
- Physical access to cluster nodes
- Kubernetes control plane CVEs (vulnerabilities in kube-apiserver,
  etcd, kubelet itself)
- Cloud provider hypervisor or hardware vulnerabilities
- Exploitation of AWS service-level vulnerabilities (not IAM/RBAC
  misconfigurations)
- Multi-tenant cluster scenarios where the attacker controls a
  namespace but not the workload being analyzed
- Scenarios where SCPs (Service Control Policies) at the AWS
  Organizations level restrict the effective permissions of IAM
  roles (our tool reads IAM directly and does not yet evaluate SCPs)

## Relationship to Tool Scope

This tool is a DETECTION and REMEDIATION tool, not an exploitation
tool. It reads configuration (AWS IAM policies, Kubernetes RBAC
bindings, IRSA annotations) as a read-only analysis pass and reports
which paths WOULD be exploitable by an attacker operating within
this threat model. It does not:
- Attempt to actually assume any IAM role
- Attempt to execute any Kubernetes API calls beyond read-only
  listing of RBAC resources and ServiceAccounts
- Generate, store, or transmit any credentials
- Modify any AWS or Kubernetes resource

The tool requires read-level AWS IAM permissions
(iam:List*, iam:Get*) and Kubernetes RBAC read permissions
(get/list on serviceaccounts, roles, rolebindings, clusterroles,
clusterrolebindings) to operate. It does not require -- and should
not be granted -- any write permissions on either platform.
