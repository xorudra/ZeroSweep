# Kubernetes Production Hardening — ZeroSweep (§135)

## Pod security

- Namespace enforces Pod Security Standards **restricted**
  (`deploy/kubernetes/base/namespace.yaml`). Every workload in the base
  complies: non-root, `allowPrivilegeEscalation: false`, all capabilities
  dropped, seccomp RuntimeDefault, read-only root filesystem, explicit
  requests/limits incl. ephemeral storage.
- Admission (Kyverno, `deploy/policies/kyverno-policies.yaml`) REJECTS
  privileged pods, host namespaces, hostPath, runtime-socket mounts,
  untrusted registries, `latest` tags, and missing limits — including for
  Jobs, so the scan-job path cannot be used to smuggle a privileged pod.

## Identity & RBAC

- One ServiceAccount per workload; token automount disabled except the
  worker controller, whose Role grants ONLY Job management + Pod status
  in-namespace. No workload can read Secrets or other namespaces.

## Network

- Default-deny NetworkPolicy; per-workload allows; the cloud metadata
  address is excluded from every egress rule; scanner egress is limited
  to governed ports and approved target sets per pool.
- Ingress is the only external entry; `/metrics` is reachable only from
  the monitoring namespace.

## Scan-job isolation

See `deploy/kubernetes/base/scan-job.yaml`: fresh pod per stage,
TTL-cleaned, hard deadline, bounded resources, no host access of any
kind, credentials as secret references for the stage only.

## Exceptions

There are **no standing exceptions**. Any future exception must be:
narrow (single pool/namespace), named in this document with an owner and
expiry, and expressed as a separate policy object — never by weakening
the baseline policies. Raw-socket tooling follows the
ScannerCapabilityPolicy path (isolated node pool, ELEVATED approval),
not a pod-security exception.

## Node strategy (§100/§101)

- General pools on general nodes; the network/scanner pool on
  scanner-labelled + tainted nodes (`dsrclone.io/scanner=true`), so scan
  egress and any future elevated network needs stay off shared nodes.
- PriorityClasses: platform critical (API/scheduler) above scan work;
  scan work never preempts.
