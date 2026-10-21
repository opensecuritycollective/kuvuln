"""Native Kubernetes manifest analysis.

Unlike external linters, KuVuln evaluates the full document set: workloads,
RBAC objects and NetworkPolicies together. This allows cross-resource checks
such as RBAC privilege escalation paths and namespaces with no default-deny
policy.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .config import Config
from .models import Finding, Location
from .utils import normalize_path

LOGGER = logging.getLogger("kuvuln.kubernetes")

WORKLOAD_KINDS = {
    "Pod": "spec",
    "Deployment": "spec.template.spec",
    "StatefulSet": "spec.template.spec",
    "DaemonSet": "spec.template.spec",
    "ReplicaSet": "spec.template.spec",
    "ReplicationController": "spec.template.spec",
    "Job": "spec.template.spec",
    "CronJob": "spec.jobTemplate.spec.template.spec",
}

CONTAINER_FIELDS = ("containers", "initContainers", "ephemeralContainers")

DANGEROUS_CAPABILITIES = {
    "ALL",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "DAC_READ_SEARCH",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "NET_ADMIN",
    "NET_RAW",
    "SETUID",
    "SETGID",
    "LINUX_IMMUTABLE",
    "AUDIT_CONTROL",
    "AUDIT_WRITE",
    "IPC_LOCK",
}

ALLOWED_VOLUME_TYPES = {
    "configMap",
    "csi",
    "downwardAPI",
    "emptyDir",
    "ephemeral",
    "persistentVolumeClaim",
    "projected",
    "secret",
}

SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
    "net.ipv4.ip_local_reserved_ports",
}

REMOVED_API_VERSIONS: dict[str, dict[str, str]] = {
    "extensions/v1beta1": {
        "Deployment": "apps/v1",
        "DaemonSet": "apps/v1",
        "ReplicaSet": "apps/v1",
        "StatefulSet": "apps/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
        "Ingress": "networking.k8s.io/v1",
        "PodSecurityPolicy": "removed in v1.25",
    },
    "apps/v1beta1": {
        "Deployment": "apps/v1",
        "DaemonSet": "apps/v1",
        "ReplicaSet": "apps/v1",
        "StatefulSet": "apps/v1",
    },
    "apps/v1beta2": {
        "Deployment": "apps/v1",
        "DaemonSet": "apps/v1",
        "ReplicaSet": "apps/v1",
        "StatefulSet": "apps/v1",
    },
    "batch/v1beta1": {"CronJob": "batch/v1"},
    "autoscaling/v2beta1": {"HorizontalPodAutoscaler": "autoscaling/v2"},
    "autoscaling/v2beta2": {"HorizontalPodAutoscaler": "autoscaling/v2"},
    "policy/v1beta1": {
        "PodDisruptionBudget": "policy/v1",
        "PodSecurityPolicy": "removed in v1.25",
    },
    "networking.k8s.io/v1beta1": {
        "Ingress": "networking.k8s.io/v1",
        "IngressClass": "networking.k8s.io/v1",
    },
    "rbac.authorization.k8s.io/v1beta1": {
        "Role": "rbac.authorization.k8s.io/v1",
        "ClusterRole": "rbac.authorization.k8s.io/v1",
        "RoleBinding": "rbac.authorization.k8s.io/v1",
        "ClusterRoleBinding": "rbac.authorization.k8s.io/v1",
    },
    "apiextensions.k8s.io/v1beta1": {
        "CustomResourceDefinition": "apiextensions.k8s.io/v1"
    },
    "admissionregistration.k8s.io/v1beta1": {
        "ValidatingWebhookConfiguration": "admissionregistration.k8s.io/v1",
        "MutatingWebhookConfiguration": "admissionregistration.k8s.io/v1",
    },
    "certificates.k8s.io/v1beta1": {
        "CertificateSigningRequest": "certificates.k8s.io/v1"
    },
    "coordination.k8s.io/v1beta1": {"Lease": "coordination.k8s.io/v1"},
    "scheduling.k8s.io/v1beta1": {"PriorityClass": "scheduling.k8s.io/v1"},
    "storage.k8s.io/v1beta1": {
        "CSIDriver": "storage.k8s.io/v1",
        "StorageClass": "storage.k8s.io/v1",
        "VolumeAttachment": "storage.k8s.io/v1",
    },
    "node.k8s.io/v1beta1": {"RuntimeClass": "node.k8s.io/v1"},
    "flowcontrol.apiserver.k8s.io/v1beta1": {
        "FlowSchema": "flowcontrol.apiserver.k8s.io/v1",
        "PriorityLevelConfiguration": "flowcontrol.apiserver.k8s.io/v1",
    },
}

SENSITIVE_HOST_PATHS = {
    "/",
    "/var/run/docker.sock",
    "/var/lib/kubelet",
    "/var/lib/kubelet/",
    "/etc/kubernetes",
    "/etc/kubernetes/",
    "/root",
    "/proc",
    "/sys",
}

DEFAULT_EXCLUDED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
BUILTIN_ROLE_NAMES = {"cluster-admin", "admin", "edit", "view"}

CLUSTER_SCOPED_KINDS = {
    "Namespace",
    "Node",
    "PersistentVolume",
    "ClusterRole",
    "ClusterRoleBinding",
    "StorageClass",
    "CSIDriver",
    "CSINode",
    "VolumeAttachment",
    "CustomResourceDefinition",
    "APIService",
    "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration",
    "PriorityClass",
    "RuntimeClass",
    "PodSecurityPolicy",
    "CertificateSigningRequest",
}

_CIS = "CIS-Kubernetes"
_NSA = "NSA-CISA"


@dataclass
class ResourceDoc:
    kind: str
    api_version: str
    name: str
    namespace: str
    path: str
    line: int
    doc: Any
    sequence: int

    @property
    def identity(self) -> str:
        namespace = self.namespace or "_cluster"
        return f"{self.kind}/{namespace}/{self.name}"


def discover_resources(roots: Iterable[str | Path], config: Config) -> tuple[list[ResourceDoc], list[str]]:
    warnings: list[str] = []
    docs: list[ResourceDoc] = []
    max_size = int(config.get("kubernetes.max_file_size_kb", 4096)) * 1024
    yaml_loader = YAML(typ="rt")
    sequence = 0
    seen_files: set[str] = set()
    for root in roots:
        root_path = Path(root).resolve()
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            current = Path(dirpath)
            kept = []
            for name in dirnames:
                if name in {".git", "node_modules", ".venv", "venv", "__pycache__"} or name.startswith("."):
                    continue
                if config.path_excluded(_relative(current / name, root_path)):
                    continue
                kept.append(name)
            dirnames[:] = sorted(kept)
            for filename in sorted(filenames):
                path = current / filename
                if path.is_symlink():
                    continue
                rel = _relative(path, root_path)
                if config.path_excluded(rel):
                    continue
                if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
                    continue
                if rel in seen_files:
                    continue
                try:
                    if path.stat().st_size > max_size:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    warnings.append(f"{rel}: could not read ({exc})")
                    continue
                seen_files.add(rel)
                if path.suffix.lower() == ".json" and (
                    '"apiVersion"' not in text or '"kind"' not in text
                ):
                    # Ignore non-Kubernetes JSON such as go list/govulncheck
                    # streams and SBOMs.
                    LOGGER.debug("Skipping non-Kubernetes JSON: %s", rel)
                    continue
                if "{{" in text and "}}" in text:
                    try:
                        loaded = list(yaml_loader.load_all(text))
                    except Exception:
                        LOGGER.debug("Skipping templated file: %s", rel)
                        continue
                else:
                    try:
                        loaded = list(yaml_loader.load_all(text))
                    except Exception as exc:
                        warnings.append(f"{rel}: invalid YAML ({exc})")
                        continue
                for doc in loaded:
                    if not isinstance(doc, dict):
                        continue
                    kind = doc.get("kind")
                    if kind == "List" and isinstance(doc.get("items"), list):
                        items = [item for item in doc["items"] if isinstance(item, dict)]
                        for item in items:
                            resource = _make_resource(item, rel, sequence)
                            if resource:
                                docs.append(resource)
                                sequence += 1
                        continue
                    resource = _make_resource(doc, rel, sequence)
                    if resource:
                        docs.append(resource)
                        sequence += 1
    docs.sort(key=lambda item: (item.path, item.line, item.sequence))
    return docs, warnings


def _make_resource(doc: dict[str, Any], rel: str, sequence: int) -> ResourceDoc | None:
    kind = doc.get("kind")
    if not isinstance(kind, str) or not kind:
        return None
    if kind in {"Chart", "List"}:
        return None
    api_version = doc.get("apiVersion")
    if not isinstance(api_version, str) or not api_version:
        return None
    metadata = doc.get("metadata") or {}
    name = metadata.get("name") or metadata.get("generateName") or kind.lower()
    namespace = metadata.get("namespace") or (
        "" if kind in CLUSTER_SCOPED_KINDS else "default"
    )
    line = _line_of(doc) or 1
    return ResourceDoc(
        kind=kind,
        api_version=api_version,
        name=str(name),
        namespace=str(namespace),
        path=rel,
        line=int(line),
        doc=doc,
        sequence=sequence,
    )


def analyze_resources(resources: list[ResourceDoc], config: Config) -> list[Finding]:
    findings: list[Finding] = []
    if not resources:
        return findings
    pss = str(config.get("kubernetes.pod_security_standard", "restricted"))
    excluded_namespaces = {
        str(name).lower()
        for name in config.get("kubernetes.exclude_namespaces", DEFAULT_EXCLUDED_NAMESPACES)
    }

    for resource in resources:
        namespace = resource.namespace.lower()
        if namespace and namespace in excluded_namespaces:
            continue
        if config.get("kubernetes.check_removed_apis", True):
            finding = _check_removed_api(resource)
            if finding:
                findings.append(finding)
        if resource.kind in WORKLOAD_KINDS:
            findings.extend(_analyze_workload(resource, config, pss))
        elif resource.kind == "Secret" and config.get("kubernetes.check_plaintext_secrets", True):
            finding = _check_plaintext_secret(resource)
            if finding:
                findings.append(finding)
        elif resource.kind in {"Ingress", "IngressClass"}:
            finding = _check_ingress_tls(resource)
            if finding:
                findings.append(finding)
        elif resource.kind in {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}:
            findings.extend(_check_admission_webhook(resource, config))
        elif resource.kind == "KubeletConfiguration" and config.get("kubernetes.check_kubelet_config", True):
            findings.extend(_check_kubelet_config(resource))

    if config.get("kubernetes.check_control_plane_flags", True):
        for resource in resources:
            findings.extend(_check_control_plane_flags(resource))

    if config.get("kubernetes.check_rbac", True):
        findings.extend(_analyze_rbac(resources, excluded_namespaces, config))

    if config.get("kubernetes.require_network_policy", True):
        findings.extend(_analyze_network_policies(resources, excluded_namespaces))

    return [finding for finding in findings if finding is not None]


# ---------------------------------------------------------------------------
# Line helpers
# ---------------------------------------------------------------------------


def _line_of(node: Any, key: str | None = None) -> int | None:
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    if key is None:
        line = getattr(lc, "line", None)
        return int(line) + 1 if isinstance(line, int) else None
    try:
        info = lc.key(key)
        line = info[0] if isinstance(info, tuple) else None
    except Exception:
        line = getattr(lc, "line", None)
    return int(line) + 1 if isinstance(line, int) else None


def _value(node: Any, key: str, default: Any = None) -> Any:
    if isinstance(node, dict):
        return node.get(key, default)
    return default


def _pod_spec(resource: ResourceDoc) -> Any:
    path = WORKLOAD_KINDS.get(resource.kind)
    if not path:
        return None
    node = resource.doc
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, dict) else None


def _container_specs(pod_spec: Any) -> list[tuple[Any, str]]:
    containers: list[tuple[Any, str]] = []
    if not isinstance(pod_spec, dict):
        return containers
    for field in CONTAINER_FIELDS:
        values = pod_spec.get(field) or []
        if not isinstance(values, list):
            continue
        for container in values:
            if isinstance(container, dict):
                containers.append((container, field))
    return containers


def _container_name(container: Any) -> str:
    return str(_value(container, "name", "container"))


def _container_image(container: Any) -> str:
    return str(_value(container, "image", ""))


def _effective_security_context(pod_spec: Any, container: Any) -> Any:
    context: dict[str, Any] = {}
    pod_context = _value(pod_spec, "securityContext")
    if isinstance(pod_context, dict):
        context.update(pod_context)
    container_context = _value(container, "securityContext")
    if isinstance(container_context, dict):
        context.update(container_context)
    return context


def _is_true(value: Any) -> bool:
    return value is True


def _location(resource: ResourceDoc, line: int | None = None) -> Location:
    return Location(path=resource.path, start_line=line or resource.line)


def _finding(
    resource: ResourceDoc,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    line: int | None = None,
    category: str = "kubernetes",
    properties: dict[str, Any] | None = None,
    compliance: list[str] | None = None,
    pss: str | None = None,
) -> Finding:
    props: dict[str, Any] = {
        "resource": resource.identity,
        "kind": resource.kind,
        "namespace": resource.namespace,
        "control": rule_id,
        "compliance": compliance or [],
        "pss": pss,
        **(properties or {}),
    }
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        source="kuvuln",
        location=_location(resource, line),
        remediation=remediation,
        properties=props,
    )


# ---------------------------------------------------------------------------
# Workload hardening
# ---------------------------------------------------------------------------


def _analyze_workload(resource: ResourceDoc, config: Config, pss: str) -> list[Finding]:
    pod_spec = _pod_spec(resource)
    if not pod_spec:
        return []
    findings: list[Finding] = []
    pod_context = _value(pod_spec, "securityContext")
    pod_context = pod_context if isinstance(pod_context, dict) else {}

    if _is_true(_value(pod_spec, "hostNetwork")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-005",
                "HIGH",
                "Pod shares the host network namespace",
                "hostNetwork gives the container access to the node network stack, "
                "including services bound to localhost and the ability to sniff traffic.",
                "Set hostNetwork: false unless the workload is a control-plane component "
                "that requires it.",
                _line_of(pod_spec, "hostNetwork"),
                compliance=[_NSA, _CIS],
                pss="baseline",
            )
        )
    if _is_true(_value(pod_spec, "hostPID")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-006",
                "HIGH",
                "Pod shares the host PID namespace",
                "hostPID exposes all processes on the node to the container and can be "
                "used to inspect or interfere with host workloads.",
                "Set hostPID: false.",
                _line_of(pod_spec, "hostPID"),
                compliance=[_NSA, _CIS],
                pss="baseline",
            )
        )
    if _is_true(_value(pod_spec, "hostIPC")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-007",
                "HIGH",
                "Pod shares the host IPC namespace",
                "hostIPC allows the container to communicate with processes on the "
                "node through System V IPC and POSIX message queues.",
                "Set hostIPC: false.",
                _line_of(pod_spec, "hostIPC"),
                compliance=[_NSA, _CIS],
                pss="baseline",
            )
        )
    if _is_true(_value(pod_spec, "shareProcessNamespace")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-018",
                "MEDIUM",
                "Pod shares its process namespace between containers",
                "shareProcessNamespace makes every process visible to other containers "
                "in the pod, leaking signals such as file descriptors and environment.",
                "Set shareProcessNamespace: false unless required.",
                _line_of(pod_spec, "shareProcessNamespace"),
                compliance=[_NSA],
                pss="restricted",
            )
        )
    if _is_true(_value(pod_spec, "hostProcess")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-022",
                "HIGH",
                "Windows HostProcess container enabled",
                "HostProcess containers run with elevated privileges on the Windows "
                "node, effectively bypassing container isolation.",
                "Set hostProcess: false.",
                _line_of(pod_spec, "hostProcess"),
                compliance=[_NSA, _CIS],
                pss="baseline",
            )
        )

    sysctls = _value(pod_spec, "sysctls")
    if isinstance(sysctls, list):
        for index, sysctl in enumerate(sysctls):
            if not isinstance(sysctl, dict):
                continue
            sysctl_name = str(_value(sysctl, "name", ""))
            if sysctl_name and sysctl_name not in SAFE_SYSCTLS:
                findings.append(
                    _finding(
                        resource,
                        "KUV-K8S-020",
                        "HIGH",
                        f"Unsafe sysctl enabled: {sysctl_name}",
                        "Unsafe sysctls can expose kernel interfaces to container "
                        "workloads and are not namespaced, affecting the whole node.",
                        f"Remove the {sysctl_name} sysctl or move it to an explicitly "
                        "approved allowlist.",
                        _line_of(sysctl) or _line_of(pod_spec, "sysctls"),
                        compliance=[_CIS, _NSA],
                        pss="restricted",
                    )
                )

    findings.extend(_check_volumes(resource, pod_spec, pss))
    findings.extend(_check_automount(resource, pod_spec))
    findings.extend(_check_resource_limits(resource, pod_spec, config))

    for container, field in _container_specs(pod_spec):
        name = _container_name(container)
        context = _effective_security_context(pod_spec, container)
        findings.extend(
            _analyze_container(
                resource, container, field, name, context, pod_context, pss, config
            )
        )
    return findings


def _analyze_container(
    resource: ResourceDoc,
    container: Any,
    field: str,
    name: str,
    context: dict[str, Any],
    pod_context: dict[str, Any],
    pss: str,
    config: Config,
) -> list[Finding]:
    findings: list[Finding] = []
    base_props = {"container": name, "container_field": field}
    container_line = _line_of(container)

    if _is_true(_value(context, "privileged")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-001",
                "HIGH",
                f"Container '{name}' runs privileged",
                "A privileged container is effectively root on the node: it has all "
                "Linux capabilities, can mount devices, modify kernel settings and "
                "break out of the container.",
                "Remove privileged: true and grant only the specific capabilities or "
                "volume mounts the workload needs.",
                container_line,
                properties=base_props,
                compliance=[_NSA, _CIS],
                pss="baseline",
            )
        )

    escalation = _value(context, "allowPrivilegeEscalation")
    if _is_true(escalation):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-002",
                "HIGH",
                f"Container '{name}' allows privilege escalation",
                "allowPrivilegeEscalation lets a process obtain more privileges than "
                "its parent, which is a common privilege-escalation primitive.",
                "Set allowPrivilegeEscalation: false in the container securityContext.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA, _CIS],
                pss="restricted",
            )
        )
    elif escalation is None and pss == "restricted":
        findings.append(
            _finding(
                resource,
                "KUV-K8S-002",
                "MEDIUM",
                f"Container '{name}' does not disable privilege escalation",
                "Privilege escalation defaults to enabled when it is not explicitly set.",
                "Set allowPrivilegeEscalation: false.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA],
                pss="restricted",
            )
        )

    run_as_non_root = _value(context, "runAsNonRoot")
    if run_as_non_root is False:
        findings.append(
            _finding(
                resource,
                "KUV-K8S-003",
                "HIGH",
                f"Container '{name}' explicitly runs as root",
                "runAsNonRoot: false explicitly allows the container to run with UID 0.",
                "Set runAsNonRoot: true and use an unprivileged user/group.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA, _CIS],
                pss="restricted",
            )
        )
    elif run_as_non_root is None and pss == "restricted":
        findings.append(
            _finding(
                resource,
                "KUV-K8S-003",
                "MEDIUM",
                f"Container '{name}' does not require a non-root user",
                "When runAsNonRoot is not set the container can be started as UID 0.",
                "Set runAsNonRoot: true (and runAsUser to a non-zero UID).",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA],
                pss="restricted",
            )
        )
    run_as_user = _value(context, "runAsUser")
    if run_as_user == 0:
        findings.append(
            _finding(
                resource,
                "KUV-K8S-004",
                "HIGH",
                f"Container '{name}' runs as UID 0",
                "Running with UID 0 maximises the impact of a container compromise.",
                "Set runAsUser to a non-zero UID.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA, _CIS],
                pss="restricted",
            )
        )

    capabilities = _value(context, "capabilities")
    if isinstance(capabilities, dict):
        added = capabilities.get("add") or []
        dropped = capabilities.get("drop") or []
        dangerous = [str(item).upper() for item in added if str(item).upper() in DANGEROUS_CAPABILITIES]
        if dangerous:
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-009",
                    "HIGH",
                    f"Container '{name}' adds dangerous capabilities: {', '.join(dangerous)}",
                    "These capabilities grant kernel-level powers such as arbitrary "
                    "code execution, namespace manipulation or raw network access.",
                    "Remove the capability from add and grant only what the workload needs.",
                    _line_of(container, "securityContext") or container_line,
                    properties=base_props,
                    compliance=[_NSA, _CIS],
                    pss="restricted",
                )
            )
        elif added:
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-010",
                    "MEDIUM",
                    f"Container '{name}' adds Linux capabilities",
                    "Every added capability widens the attack surface of the container.",
                    "Grant the minimum set of capabilities required and drop ALL first.",
                    _line_of(container, "securityContext") or container_line,
                    properties=base_props,
                    compliance=[_NSA],
                    pss="restricted",
                )
            )
        if "ALL" not in {str(item).upper() for item in dropped} and pss == "restricted":
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-010",
                    "LOW",
                    f"Container '{name}' does not drop all capabilities",
                    "Pod Security Standards restricted requires capabilities.drop to "
                    "include ALL.",
                    "Add capabilities.drop: [ALL] and add back only required capabilities.",
                    _line_of(container, "securityContext") or container_line,
                    properties=base_props,
                    compliance=[_NSA],
                    pss="restricted",
                )
            )

    seccomp = _value(context, "seccompProfile")
    if isinstance(seccomp, dict) and str(_value(seccomp, "type", "")) == "Unconfined":
        findings.append(
            _finding(
                resource,
                "KUV-K8S-011",
                "HIGH",
                f"Container '{name}' disables seccomp",
                "Unconfined seccomp exposes the full syscall surface to the container.",
                "Set seccompProfile.type to RuntimeDefault.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA, _CIS],
                pss="restricted",
            )
        )
    elif not isinstance(seccomp, dict) and pss == "restricted":
        findings.append(
            _finding(
                resource,
                "KUV-K8S-011",
                "MEDIUM",
                f"Container '{name}' does not set a seccomp profile",
                "Without a seccomp profile the container may use the host default, "
                "which can be unconfined.",
                "Set seccompProfile.type to RuntimeDefault.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA],
                pss="restricted",
            )
        )

    read_only = _value(context, "readOnlyRootFilesystem")
    if read_only is False or (read_only is None and pss == "restricted"):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-012",
                "LOW" if read_only is False else "LOW",
                f"Container '{name}' does not use a read-only root filesystem",
                "A writable root filesystem makes it easier to install packages, "
                "persist payloads and tamper with the application.",
                "Set readOnlyRootFilesystem: true and mount emptyDir volumes for writes.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA],
                pss="restricted",
            )
        )
    proc_mount = _value(context, "procMount")
    if str(proc_mount) == "Unmasked":
        findings.append(
            _finding(
                resource,
                "KUV-K8S-021",
                "HIGH",
                f"Container '{name}' uses an unmasked /proc",
                "Unmasked procMount exposes the host process table and kernel interfaces.",
                "Remove procMount: Unmasked or set it to Default.",
                _line_of(container, "securityContext") or container_line,
                properties=base_props,
                compliance=[_NSA, _CIS],
                pss="restricted",
            )
        )

    findings.extend(_check_image(resource, container, name, config, container_line))
    return findings


def _check_image(
    resource: ResourceDoc, container: Any, name: str, config: Config, line: int | None
) -> list[Finding]:
    image = _container_image(container)
    if not image:
        return []
    findings: list[Finding] = []
    repository, _, tag = _image_parts(image)
    if tag == "latest" or not tag:
        findings.append(
            _finding(
                resource,
                "KUV-K8S-014",
                "MEDIUM",
                f"Container '{name}' uses an unpinned image tag",
                "Floating tags make deployments non-reproducible and can silently "
                "pull a vulnerable or compromised image.",
                f"Pin the image to an immutable digest or a released version tag: "
                f"{repository}@sha256:<digest>.",
                _line_of(container, "image") or line,
                properties={"container": name, "image": image},
                compliance=[_NSA, _CIS],
            )
        )
    elif config.get("kubernetes.require_image_digest", False) and "@sha256:" not in image:
        findings.append(
            _finding(
                resource,
                "KUV-K8S-015",
                "LOW",
                f"Container '{name}' image is not pinned by digest",
                "Version tags can be re-pointed by the registry, so they do not "
                "guarantee supply-chain integrity.",
                f"Reference the image by digest: {repository}@sha256:<digest>.",
                _line_of(container, "image") or line,
                properties={"container": name, "image": image},
                compliance=[_NSA],
            )
        )
    trusted = config.get("kubernetes.trusted_registries", []) or []
    if trusted and repository:
        registry = _registry_of(repository)
        if registry and registry not in {str(item).lower() for item in trusted}:
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-016",
                    "HIGH",
                    f"Container '{name}' image comes from an untrusted registry",
                    f"The image registry {registry} is not in the trusted registry "
                    "allowlist, increasing supply-chain risk.",
                    "Pull the image from an approved registry or add it to "
                    "kubernetes.trusted_registries.",
                    _line_of(container, "image") or line,
                    properties={"container": name, "image": image, "registry": registry},
                    compliance=[_NSA],
                )
            )
    return findings


def _registry_of(repository: str) -> str:
    """Return the registry host, ignoring a :port suffix."""
    host = repository.split("/", 1)[0].lower()
    if host.startswith("["):  # IPv6 literal
        return host
    return host.split(":", 1)[0]


def _image_parts(image: str) -> tuple[str, str, str]:
    reference = image
    if "@" in reference:
        reference = reference.split("@", 1)[0]
    last_slash = reference.rfind("/")
    last_colon = reference.rfind(":")
    if last_colon > last_slash and last_colon >= 0:
        repository = reference[:last_colon]
        tag = reference[last_colon + 1 :]
        return repository, tag, tag
    return reference, "", ""


def _check_volumes(resource: ResourceDoc, pod_spec: Any, pss: str) -> list[Finding]:
    findings: list[Finding] = []
    volumes = _value(pod_spec, "volumes")
    if not isinstance(volumes, list):
        return findings
    for index, volume in enumerate(volumes):
        if not isinstance(volume, dict):
            continue
        volume_name = str(_value(volume, "name", f"volume-{index}"))
        host_path = _value(volume, "hostPath")
        if isinstance(host_path, dict):
            path = str(_value(host_path, "path", ""))
            severity = "CRITICAL" if path in SENSITIVE_HOST_PATHS else "HIGH"
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-008",
                    severity,
                    f"Volume '{volume_name}' mounts a hostPath",
                    f"hostPath exposes host filesystem path {path!r} to the pod. "
                    "It can be used to read secrets, modify node configuration or "
                    "escape the container.",
                    "Remove hostPath or replace it with an allowed volume type "
                    "(persistentVolumeClaim, configMap, secret, projected, emptyDir).",
                    _line_of(volume, "hostPath") or _line_of(volume),
                    properties={"container": "", "volume": volume_name, "host_path": path},
                    compliance=[_NSA, _CIS],
                    pss="baseline",
                )
            )
        if pss == "restricted":
            volume_type = _value(volume, "type")
            if volume_type and str(volume_type) not in ALLOWED_VOLUME_TYPES:
                findings.append(
                    _finding(
                        resource,
                        "KUV-K8S-019",
                        "MEDIUM",
                        f"Volume '{volume_name}' uses a disallowed volume type",
                        "Pod Security Standards restricted only allows configMap, csi, "
                        "downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, "
                        "projected and secret volumes.",
                        "Move the data to an allowed volume type.",
                        _line_of(volume, "type") or _line_of(volume),
                        properties={"volume": volume_name, "volume_type": str(volume_type)},
                        compliance=[_NSA],
                        pss="restricted",
                    )
                )
            elif not volume_type:
                keys = {str(key) for key in volume.keys() if key not in {"name", "type"}}
                if keys and not keys.issubset(ALLOWED_VOLUME_TYPES):
                    findings.append(
                        _finding(
                            resource,
                            "KUV-K8S-019",
                            "MEDIUM",
                            f"Volume '{volume_name}' uses a disallowed volume type",
                            "Pod Security Standards restricted only allows a limited "
                            "set of volume types.",
                            "Move the data to an allowed volume type.",
                            _line_of(volume),
                            properties={"volume": volume_name},
                            compliance=[_NSA],
                            pss="restricted",
                        )
                    )
    return findings


def _check_automount(resource: ResourceDoc, pod_spec: Any) -> list[Finding]:
    automount = _value(pod_spec, "automountServiceAccountToken")
    if _is_true(automount):
        return [
            _finding(
                resource,
                "KUV-K8S-017",
                "LOW",
                "Pod explicitly automounts the service account token",
                "Automounted tokens can be exfiltrated and replayed by a compromised "
                "workload. The token should only be mounted when the API is used.",
                "Set automountServiceAccountToken: false unless the workload calls "
                "the Kubernetes API.",
                _line_of(pod_spec, "automountServiceAccountToken"),
                compliance=[_NSA],
            )
        ]
    return []


def _check_resource_limits(
    resource: ResourceDoc, pod_spec: Any, config: Config
) -> list[Finding]:
    if not config.get("kubernetes.require_resource_limits", True):
        return []
    findings: list[Finding] = []
    for container, _ in _container_specs(pod_spec):
        name = _container_name(container)
        resources = _value(container, "resources")
        if not isinstance(resources, dict) or not resources.get("limits"):
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-013",
                    "MEDIUM",
                    f"Container '{name}' has no resource limits",
                    "Without limits a container can consume all node resources, "
                    "causing denial of service for other workloads.",
                    "Set resources.limits.cpu and resources.limits.memory.",
                    _line_of(container, "resources") or _line_of(container),
                    properties={"container": name},
                    compliance=[_NSA, _CIS],
                )
            )
    return findings


def _check_plaintext_secret(resource: ResourceDoc) -> Finding | None:
    secret = resource.doc
    annotations = _value(_value(secret, "metadata"), "annotations") or {}
    if not isinstance(annotations, dict):
        annotations = {}
    annotation_text = " ".join(
        f"{key} {value}" for key, value in annotations.items()
    ).lower()
    if (
        "sealedsecrets.bitnami.com" in annotation_text
        or "external-secrets.io" in annotation_text
        or "argocd.argoproj.io" in annotation_text
    ):
        return None
    if str(_value(secret, "type", "")).lower() == "kubernetes.io/service-account-token":
        return None
    data = _value(secret, "data")
    string_data = _value(secret, "stringData")
    if not data and not string_data:
        return None
    return _finding(
        resource,
        "KUV-K8S-024",
        "HIGH",
        "Secret contains plaintext data in the manifest",
        "Secret objects in Git are base64-encoded, not encrypted. Anyone with "
        "repository read access can recover the credentials and they appear in "
        "cluster audit history.",
        "Store credentials in an external secret manager (External Secrets, "
        "Sealed Secrets, SOPS, Vault) and keep only references in Git. Rotate "
        "the exposed credentials.",
        _line_of(secret, "data") or _line_of(secret, "stringData") or resource.line,
        compliance=[_NSA, _CIS],
    )


def _check_ingress_tls(resource: ResourceDoc) -> Finding | None:
    spec = _value(resource.doc, "spec")
    if not isinstance(spec, dict):
        return None
    tls = _value(spec, "tls")
    if tls:
        return None
    return _finding(
        resource,
        "KUV-K8S-029",
        "MEDIUM",
        "Ingress does not configure TLS",
        "An Ingress without TLS terminates traffic in plain HTTP, exposing "
        "credentials, tokens and session cookies.",
        "Add a spec.tls entry pointing at a valid certificate secret and force "
        "HTTPS redirects.",
        _line_of(spec, "rules") or resource.line,
        compliance=[_NSA, _CIS],
    )


def _check_admission_webhook(resource: ResourceDoc, config: Config) -> list[Finding]:
    if not config.get("kubernetes.check_admission_webhooks", True):
        return []
    findings: list[Finding] = []
    webhooks = _value(resource.doc, "webhooks")
    if not isinstance(webhooks, list):
        return findings
    for index, webhook in enumerate(webhooks):
        if not isinstance(webhook, dict):
            continue
        name = str(_value(webhook, "name", f"webhook-{index}"))
        failure_policy = str(_value(webhook, "failurePolicy", ""))
        if failure_policy.lower() == "ignore":
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-028",
                    "MEDIUM",
                    f"Admission webhook '{name}' uses failurePolicy: Ignore",
                    "A webhook with failurePolicy Ignore silently bypasses the "
                    "admission policy when the webhook is unavailable, defeating "
                    "its security purpose.",
                    "Set failurePolicy: Fail (with a timeout and namespaceSelector "
                    "that keeps kube-system operational).",
                    _line_of(webhook, "failurePolicy") or _line_of(webhook),
                    properties={"webhook": name},
                    compliance=[_NSA, _CIS],
                )
            )
    return findings


def _check_kubelet_config(resource: ResourceDoc) -> list[Finding]:
    doc = resource.doc
    findings: list[Finding] = []
    auth = _value(doc, "authentication") or {}
    anonymous = _value(auth, "anonymous") or {}
    if _is_true(_value(anonymous, "enabled")):
        findings.append(
            _finding(
                resource,
                "KUV-K8S-027",
                "CRITICAL",
                "Kubelet allows anonymous authentication",
                "Anonymous kubelet access exposes read-only (and historically "
                "read-write) node APIs to unauthenticated clients.",
                "Set authentication.anonymous.enabled to false and enable webhook "
                "authentication.",
                _line_of(doc, "authentication") or resource.line,
                properties={"component": "kubelet"},
                compliance=[_CIS, _NSA],
            )
        )
    webhook = _value(auth, "webhook") or {}
    if _is_true(_value(webhook, "enabled")) is False:
        findings.append(
            _finding(
                resource,
                "KUV-K8S-027",
                "HIGH",
                "Kubelet webhook authentication is disabled",
                "Without webhook authentication the kubelet cannot verify API server "
                "credentials and may fall back to anonymous access.",
                "Set authentication.webhook.enabled to true.",
                _line_of(doc, "authentication") or resource.line,
                properties={"component": "kubelet"},
                compliance=[_CIS, _NSA],
            )
        )
    authorization = _value(doc, "authorization") or {}
    if str(_value(authorization, "mode", "")).lower() == "alwaysallow":
        findings.append(
            _finding(
                resource,
                "KUV-K8S-027",
                "CRITICAL",
                "Kubelet authorization mode is AlwaysAllow",
                "AlwaysAllow lets any authenticated caller perform every kubelet "
                "action, including executing commands in pods.",
                "Set authorization.mode to Webhook.",
                _line_of(doc, "authorization") or resource.line,
                properties={"component": "kubelet"},
                compliance=[_CIS, _NSA],
            )
        )
    read_only_port = _value(doc, "readOnlyPort")
    if isinstance(read_only_port, int) and read_only_port > 0:
        findings.append(
            _finding(
                resource,
                "KUV-K8S-027",
                "HIGH",
                f"Kubelet read-only port is enabled ({read_only_port})",
                "The read-only kubelet port exposes node information without "
                "authentication and was removed from modern Kubernetes versions.",
                "Set readOnlyPort to 0 and remove the deprecated port.",
                _line_of(doc, "readOnlyPort") or resource.line,
                properties={"component": "kubelet"},
                compliance=[_CIS, _NSA],
            )
        )
    return findings


def _check_control_plane_flags(resource: ResourceDoc) -> list[Finding]:
    if resource.kind not in WORKLOAD_KINDS:
        return []
    pod_spec = _pod_spec(resource)
    if not pod_spec:
        return []
    findings: list[Finding] = []
    for container, _ in _container_specs(pod_spec):
        args = _value(container, "args") or []
        command = _value(container, "command") or []
        tokens = [str(item) for item in (command + args) if isinstance(item, str)]
        joined = " ".join(tokens)
        if "--anonymous-auth=true" in joined:
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-026",
                    "CRITICAL",
                    "API server allows anonymous authentication",
                    "Anonymous authentication lets unauthenticated clients call the "
                    "Kubernetes API server.",
                    "Set --anonymous-auth=false.",
                    _line_of(container, "args") or _line_of(container),
                    properties={"container": _container_name(container), "component": "kube-apiserver"},
                    compliance=[_CIS, _NSA],
                )
            )
        if "--authorization-mode=AlwaysAllow" in joined or "--authorization-mode=AlwaysAllow " in joined:
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-026",
                    "CRITICAL",
                    "API server uses AlwaysAllow authorization",
                    "AlwaysAllow disables all authorization checks on the API server.",
                    "Set --authorization-mode=Node,RBAC.",
                    _line_of(container, "args") or _line_of(container),
                    properties={"container": _container_name(container), "component": "kube-apiserver"},
                    compliance=[_CIS, _NSA],
                )
            )
        match = re.search(r"--disable-admission-plugins=([^\s]+)", joined)
        if match and "PodSecurity" in match.group(1):
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-026",
                    "HIGH",
                    "API server disables the PodSecurity admission plugin",
                    "Disabling PodSecurity removes the built-in Pod Security "
                    "Standards enforcement layer.",
                    "Remove PodSecurity from --disable-admission-plugins and enforce "
                    "standards through namespace labels or a policy engine.",
                    _line_of(container, "args") or _line_of(container),
                    properties={"container": _container_name(container), "component": "kube-apiserver"},
                    compliance=[_CIS, _NSA],
                )
            )
        match = re.search(r"--insecure-port=([^\s]+)", joined)
        if match and match.group(1) != "0":
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-026",
                    "HIGH",
                    "API server insecure port is enabled",
                    "The insecure API server port bypasses authentication and "
                    "authorization.",
                    "Set --insecure-port=0 (or remove it; modern versions removed it).",
                    _line_of(container, "args") or _line_of(container),
                    properties={"container": _container_name(container), "component": "kube-apiserver"},
                    compliance=[_CIS, _NSA],
                )
            )
        match = re.search(r"--tls-min-version=([^\s]+)", joined)
        if match and match.group(1) not in {"VersionTLS12", "VersionTLS13"}:
            findings.append(
                _finding(
                    resource,
                    "KUV-K8S-026",
                    "HIGH",
                    "API server allows weak TLS versions",
                    "TLS 1.0/1.1 are deprecated and have known weaknesses.",
                    "Set --tls-min-version=VersionTLS12 or VersionTLS13.",
                    _line_of(container, "args") or _line_of(container),
                    properties={"container": _container_name(container), "component": "kube-apiserver"},
                    compliance=[_CIS, _NSA],
                )
            )
    return findings


def _check_removed_api(resource: ResourceDoc) -> Finding | None:
    replacement = REMOVED_API_VERSIONS.get(resource.api_version, {}).get(resource.kind)
    if not replacement:
        return None
    return _finding(
        resource,
        "KUV-K8S-025",
        "HIGH",
        f"{resource.kind} uses the removed API {resource.api_version}",
        f"The {resource.api_version} API version for {resource.kind} has been "
        "removed from supported Kubernetes releases. The manifest will fail to "
        "apply on current clusters.",
        f"Migrate the manifest to {replacement}.",
        resource.line,
        properties={"api_version": resource.api_version, "replacement": replacement},
        compliance=[_NSA],
    )


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def _analyze_rbac(
    resources: list[ResourceDoc],
    excluded_namespaces: set[str],
    config: Config,
) -> list[Finding]:
    findings: list[Finding] = []
    roles: dict[tuple[str, str], ResourceDoc] = {}
    for resource in resources:
        if resource.kind in {"Role", "ClusterRole"}:
            roles[(resource.kind, resource.name)] = resource

    for resource in resources:
        if resource.kind not in {"Role", "ClusterRole"}:
            continue
        if resource.name in BUILTIN_ROLE_NAMES and resource.kind == "ClusterRole":
            continue
        namespace = resource.namespace.lower()
        if namespace and namespace in excluded_namespaces:
            continue
        rules = _value(resource.doc, "rules")
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            finding = _check_rbac_rule(resource, rule)
            if finding:
                findings.append(finding)

    for resource in resources:
        if resource.kind not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        namespace = resource.namespace.lower()
        if namespace and namespace in excluded_namespaces:
            continue
        findings.extend(_check_rbac_binding(resource, roles))
    return findings


def _check_rbac_rule(resource: ResourceDoc, rule: dict[str, Any]) -> Finding | None:
    verbs = {str(item).lower() for item in (rule.get("verbs") or [])}
    resources_set = {str(item).lower() for item in (rule.get("resources") or [])}
    api_groups = {str(item).lower() for item in (rule.get("apiGroups") or [])}

    issues: list[str] = []
    severity = "LOW"
    title = f"{resource.kind} grants excessive permissions"

    if "*" in verbs and "*" in resources_set:
        return _finding(
            resource,
            "KUV-RBAC-001",
            "CRITICAL",
            f"{resource.kind} grants full wildcard permissions",
            "Wildcard verbs and resources give complete cluster administration to "
            "every principal bound to this role.",
            "Split the role into least-privilege roles with explicit verbs and "
            "resources. Reserve cluster-admin for infrastructure operators.",
            _line_of(rule),
            category="rbac",
            properties={"role": resource.identity, "rule_index": None},
            compliance=[_CIS, _NSA],
        )

    if "*" in verbs:
        issues.append("wildcard verbs")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} grants wildcard verbs"
    if "*" in resources_set:
        issues.append("wildcard resources")
        severity = max(severity, "MEDIUM", key=_severity_rank)
        title = f"{resource.kind} grants wildcard resources"

    sensitive_verbs = verbs & {"impersonate", "bind", "escalate"}
    if sensitive_verbs:
        issues.append(
            "privilege-escalation verbs: " + ", ".join(sorted(sensitive_verbs))
        )
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can escalate privileges"

    if _uses_resource(resources_set, "secrets") and verbs & {"get", "list", "watch"}:
        issues.append("read access to Secrets")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can read Secrets"
    elif _uses_resource(resources_set, "secrets") and verbs & {"create", "update", "patch"}:
        issues.append("write access to Secrets")
        severity = max(severity, "MEDIUM", key=_severity_rank)

    if _uses_resource(resources_set, "pods/exec") and verbs & {"create", "get", "*"}:
        issues.append("command execution in pods (pods/exec)")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can execute commands in pods"
    if _uses_resource(resources_set, "pods/portforward") and verbs & {"create", "*"}:
        issues.append("port forwarding to pods")
        severity = max(severity, "MEDIUM", key=_severity_rank)
    if _uses_resource(resources_set, "pods") and verbs & {"create", "*"}:
        issues.append("pod creation (privilege-escalation primitive)")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can create pods"

    if _uses_resource(resources_set, "serviceaccounts/token") and verbs & {"create", "*"}:
        issues.append("creation of service account tokens")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can mint service account tokens"

    if _uses_resource(resources_set, "clusterrolebindings") and verbs & {
        "create", "update", "patch", "delete", "*"
    }:
        issues.append("management of cluster role bindings")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can modify cluster role bindings"
    if _uses_resource(resources_set, "rolebindings") and verbs & {
        "create", "update", "patch", "delete", "*"
    }:
        issues.append("management of role bindings")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can modify role bindings"

    webhooks = {
        "validatingwebhookconfigurations",
        "mutatingwebhookconfigurations",
    }
    if resources_set & webhooks and verbs & {"create", "update", "patch", "delete", "*"}:
        issues.append("management of admission webhooks")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can disable admission policies"

    if _uses_resource(resources_set, "nodes/proxy") and verbs & {"create", "get", "*"}:
        issues.append("node proxy access")
        severity = max(severity, "HIGH", key=_severity_rank)
        title = f"{resource.kind} can proxy to nodes"

    if not issues:
        return None
    return _finding(
        resource,
        "KUV-RBAC-001",
        severity,
        title,
        "The rule grants: " + "; ".join(issues) + ". Excessive RBAC permissions "
        "turn a single compromised workload into cluster-wide control.",
        "Replace wildcards with the exact verbs and resources required, remove "
        "secret/impersonation/webhook permissions, and use dedicated roles per "
        "service account.",
        _line_of(rule),
        category="rbac",
        properties={
            "role": resource.identity,
            "verbs": sorted(verbs),
            "resources": sorted(resources_set),
            "api_groups": sorted(api_groups),
        },
        compliance=[_CIS, _NSA],
    )


def _uses_resource(resources_set: set[str], resource: str) -> bool:
    if "*" in resources_set:
        return True
    if resource in resources_set:
        return True
    if resource.endswith("/exec") and resource.split("/", 1)[0] in resources_set:
        return True
    if resource.endswith("/token") and resource.split("/", 1)[0] in resources_set:
        return True
    if resource.endswith("/proxy") and resource.split("/", 1)[0] in resources_set:
        return True
    if resource == "serviceaccounts/token" and "serviceaccounts" in resources_set:
        return True
    if resource == "nodes/proxy" and "nodes" in resources_set:
        return True
    return False


def _severity_rank(severity: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
        severity.upper(), 0
    )


def _check_rbac_binding(
    resource: ResourceDoc, roles: dict[tuple[str, str], ResourceDoc]
) -> list[Finding]:
    findings: list[Finding] = []
    role_ref = _value(resource.doc, "roleRef") or {}
    if not isinstance(role_ref, dict):
        return findings
    role_kind = str(_value(role_ref, "kind", ""))
    role_name = str(_value(role_ref, "name", ""))
    subjects = _value(resource.doc, "subjects")
    if not isinstance(subjects, list):
        subjects = []

    is_admin = role_name == "cluster-admin"
    role_resource = roles.get((role_kind, role_name))
    role_dangerous = False
    if role_resource is not None:
        role_dangerous = _role_is_dangerous(role_resource)
    anonymous_subject = False
    system_subjects = 0
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        subject_name = str(_value(subject, "name", ""))
        if subject_name in {"system:anonymous", "system:unauthenticated"}:
            anonymous_subject = True
        elif subject_name.startswith("system:"):
            system_subjects += 1

    if anonymous_subject:
        findings.append(
            _finding(
                resource,
                "KUV-RBAC-003",
                "CRITICAL",
                "RBAC binding grants access to unauthenticated users",
                f"{resource.kind} '{resource.name}' binds a role to "
                "system:anonymous or system:unauthenticated, allowing unauthenticated "
                "clients to use the permissions.",
                "Remove the anonymous subject; bind roles only to authenticated "
                "users, groups or service accounts.",
                _line_of(resource.doc, "subjects") or resource.line,
                category="rbac",
                properties={"binding": resource.identity, "role": role_name},
                compliance=[_CIS, _NSA],
            )
        )
        return findings

    if is_admin and not system_subjects:
        findings.append(
            _finding(
                resource,
                "KUV-RBAC-002",
                "HIGH",
                f"{resource.kind} grants cluster-admin to non-system subjects",
                "cluster-admin is equivalent to root on the cluster. Granting it to "
                "application workloads makes a container compromise a cluster "
                "compromise.",
                "Create least-privilege roles for the workload and reserve "
                "cluster-admin for cluster operators.",
                _line_of(resource.doc, "roleRef") or resource.line,
                category="rbac",
                properties={"binding": resource.identity, "role": role_name},
                compliance=[_CIS, _NSA],
            )
        )
    elif role_dangerous and not system_subjects:
        findings.append(
            _finding(
                resource,
                "KUV-RBAC-002",
                "HIGH",
                f"{resource.kind} grants a privileged role to non-system subjects",
                f"Binding to {role_kind}/{role_name} gives the workload elevated "
                "cluster permissions such as secret access, pod creation or role "
                "management.",
                "Replace the roleRef with a least-privilege role or reduce the role "
                "rules before binding it to the workload.",
                _line_of(resource.doc, "roleRef") or resource.line,
                category="rbac",
                properties={"binding": resource.identity, "role": role_name},
                compliance=[_CIS, _NSA],
            )
        )
    return findings


def _role_is_dangerous(resource: ResourceDoc) -> bool:
    rules = _value(resource.doc, "rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = {str(item).lower() for item in (rule.get("verbs") or [])}
        resources_set = {str(item).lower() for item in (rule.get("resources") or [])}
        if "*" in verbs and "*" in resources_set:
            return True
        if verbs & {"impersonate", "bind", "escalate"}:
            return True
        if _uses_resource(resources_set, "secrets") and verbs & {"get", "list", "watch"}:
            return True
        if _uses_resource(resources_set, "pods") and verbs & {"create", "*"}:
            return True
        if _uses_resource(resources_set, "serviceaccounts/token") and verbs & {"create", "*"}:
            return True
        if _uses_resource(resources_set, "rolebindings") and verbs & {
            "create", "update", "patch", "delete", "*"
        }:
            return True
    return False


# ---------------------------------------------------------------------------
# NetworkPolicy coverage
# ---------------------------------------------------------------------------


def _analyze_network_policies(
    resources: list[ResourceDoc], excluded_namespaces: set[str]
) -> list[Finding]:
    workload_namespaces: dict[str, ResourceDoc] = {}
    namespace_objects: dict[str, ResourceDoc] = {}
    policies: dict[str, list[ResourceDoc]] = {}
    for resource in resources:
        if resource.kind == "Namespace":
            namespace_objects[resource.name.lower()] = resource
        if resource.kind == "NetworkPolicy":
            policies.setdefault(resource.namespace.lower(), []).append(resource)
        if resource.kind in WORKLOAD_KINDS:
            workload_namespaces.setdefault(resource.namespace.lower(), resource)

    findings: list[Finding] = []
    for namespace, workload in sorted(workload_namespaces.items()):
        if namespace in excluded_namespaces or not namespace:
            continue
        namespace_policies = policies.get(namespace, [])
        if not namespace_policies:
            findings.append(
                _finding(
                    workload,
                    "KUV-NET-001",
                    "MEDIUM",
                    f"Namespace '{namespace}' has no NetworkPolicy",
                    f"Namespace {namespace} contains workloads but no NetworkPolicy. "
                    "Default traffic is unrestricted, allowing lateral movement and "
                    "data exfiltration.",
                    "Add a default-deny ingress/egress NetworkPolicy and allow only "
                    "explicit required traffic.",
                    workload.line,
                    category="network",
                    properties={"namespace": namespace},
                    compliance=[_CIS, _NSA],
                )
            )
            continue
        ingress_deny = False
        egress_deny = False
        for policy in namespace_policies:
            spec = _value(policy.doc, "spec") or {}
            policy_types = {str(item).lower() for item in (spec.get("policyTypes") or [])}
            if "ingress" in policy_types and not spec.get("ingress"):
                ingress_deny = True
            if "egress" in policy_types and not spec.get("egress"):
                egress_deny = True
        if not ingress_deny:
            findings.append(
                _finding(
                    namespace_objects.get(namespace, workload),
                    "KUV-NET-002",
                    "LOW",
                    f"Namespace '{namespace}' has no default-deny ingress policy",
                    "Workload traffic is not restricted by a default-deny ingress "
                    "rule, so pods accept connections from any source.",
                    "Add a NetworkPolicy selecting all pods with policyTypes: "
                    "[Ingress] and no ingress rules.",
                    workload.line,
                    category="network",
                    properties={"namespace": namespace},
                    compliance=[_CIS, _NSA],
                )
            )
        if not egress_deny:
            findings.append(
                _finding(
                    namespace_objects.get(namespace, workload),
                    "KUV-NET-003",
                    "LOW",
                    f"Namespace '{namespace}' has no default-deny egress policy",
                    "Workload traffic is not restricted by a default-deny egress "
                    "rule, allowing exfiltration to arbitrary destinations.",
                    "Add a NetworkPolicy selecting all pods with policyTypes: "
                    "[Egress] and no egress rules.",
                    workload.line,
                    category="network",
                    properties={"namespace": namespace},
                    compliance=[_CIS, _NSA],
                )
            )
    return findings


def _relative(path: Path, root: Path) -> str:
    try:
        return normalize_path(path.resolve().relative_to(root))
    except ValueError:
        return normalize_path(path)
