# Container Security Scanner (Docker + Kubernetes)

Static analysis for Dockerfiles and Kubernetes manifests — catches the
misconfigurations that lead to container escapes, privilege escalation,
and secrets baked into image layers, before anything is built or
deployed. Zero dependencies beyond PyYAML; no Docker daemon or
Kubernetes cluster required to run any of this.

## Two scanners, one shared architecture

Both the Dockerfile and Kubernetes scanners follow the same pattern I've
used across my other IaC-adjacent tools (`terraform-iac-scanner`,
`aws-cspm-scanner`): parse into a normalized structure, run independent
rule functions against it, aggregate into a risk-scored report. Rules
never touch raw text/YAML directly — only the parsed data — which is what
makes every rule independently unit-testable.

## Repository layout

```
scanner/
  dockerfile_parser.py     parses Dockerfiles (line continuations, multi-stage builds)
  k8s_parser.py              parses multi-document K8s YAML, extracts pod specs
  rules/
    dockerfile_rules.py       5 Dockerfile checks
    k8s_rules.py                7 Kubernetes pod-spec checks
  engine.py                   orchestrates parsing + rules + risk scoring
  report.py                    text report generation
fixtures/
  vulnerable.Dockerfile / secure.Dockerfile
  vulnerable-deployment.yaml / secure-deployment.yaml
scripts/
  scan_cli.py
tests/
  test_dockerfile_parser.py
  test_k8s_parser.py
  test_dockerfile_rules.py
  test_k8s_rules.py
```

## Try it immediately

```bash
pip install -r requirements.txt
python scripts/scan_cli.py --dockerfile fixtures/vulnerable.Dockerfile
# 5 findings: no USER (root), :latest base image, hardcoded secrets in
# ARG and ENV, missing HEALTHCHECK

python scripts/scan_cli.py --k8s fixtures/vulnerable-deployment.yaml
# 7 findings: privileged container, hostNetwork, hostPath mounting
# /var/run/docker.sock (a classic container-escape vector), missing
# runAsNonRoot, allowPrivilegeEscalation not disabled, :latest image,
# no resource limits

python scripts/scan_cli.py --dockerfile fixtures/secure.Dockerfile --k8s fixtures/secure-deployment.yaml
# 0 findings on both — confirms no false positives on correctly-configured resources
```

## What each rule set checks

**Dockerfile** — missing `USER` (root by default, checked against the
FINAL build stage only, so intentional root usage in earlier build stages
isn't flagged), `:latest`/untagged base images, `ADD` used where `COPY`
would be safer (ADD's remote-URL fetch is exempted as a legitimate use),
secrets baked into `ENV`/`ARG` (visible in image layer history forever),
missing `HEALTHCHECK`.

**Kubernetes** — privileged containers, `hostNetwork`/`hostPID`/`hostIPC`
sharing, missing `runAsNonRoot` (checked at both pod and container level,
with container-level correctly taking precedence), `allowPrivilegeEscalation`
not explicitly disabled (it defaults to `true`), `hostPath` volumes (a
common container-escape vector, especially mounting the Docker socket),
missing resource limits, `:latest`/untagged images.

## Running the tests

```bash
pytest tests/ -v
```

50 tests covering both parsers (multi-stage Dockerfile handling, backslash
line continuations, multi-document K8s YAML, all 5 pod-spec-nesting
resource kinds including the CronJob's deeper nesting path) and all 12
rules, including deliberately tricky edge cases: a private registry
hostname with a port number (`registry.example.com:5000/app:2.1.0`)
correctly NOT being confused with an untagged image, and container-level
`runAsNonRoot: false` correctly overriding a pod-level `true`.

## Testing status

Every single component in this project — both parsers, all 12 rules, the
engine, the CLI — runs on pure Python + PyYAML with no external services,
so there's no "still needs a live environment to confirm" caveat here.
Everything is built and tested, and the fixtures were manually
cross-checked line-by-line against the findings they should produce (5
for the vulnerable Dockerfile, 7 for the vulnerable K8s manifest, 0 for
both secure versions).

## Known limitations

- **Kubernetes rules cover pod-spec-level security only** — no checks on
  RBAC (Role/ClusterRole/RoleBinding), NetworkPolicies, PodSecurityPolicy/
  Pod Security Standards admission control, or Secret object encryption at
  rest. Those are real, important areas for a more complete K8s security
  tool but operate on different resource kinds than what's parsed here.
- **No image layer / CVE scanning** — this checks configuration, not the
  actual base image contents. Pair this with Trivy/Grype for image
  vulnerability scanning; they solve a genuinely different problem (known
  CVEs in installed packages) than configuration-as-code review.
- **Dockerfile ARG scoping is simplified** — a real Dockerfile's ARG
  values are scoped per build stage in ways this parser doesn't fully
  model; the secrets-in-ARG check flags any ARG matching a secret-like
  name regardless of which stage it's declared in, which is the safer
  (over-inclusive rather than under-inclusive) choice for a security tool.

## License

MIT — see [LICENSE](./LICENSE).
