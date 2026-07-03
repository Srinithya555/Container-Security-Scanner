"""
Dockerfile security rules. Checks apply to the LAST build stage only
(see ParsedDockerfile.last_stage_instructions) — that's what ships as the
runtime image.
"""
import re
from scanner.models import Finding, Severity

_SECRET_ENV_PATTERN = re.compile(r"(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)", re.IGNORECASE)


def check_missing_user(dockerfile, resource_id: str) -> list:
    last_stage = dockerfile.last_stage_instructions()
    has_user = any(i.instruction == "USER" for i in last_stage)
    if not has_user:
        return [Finding(
            resource_type="dockerfile", resource_id=resource_id, rule_id="DOCKER-001",
            severity=Severity.HIGH,
            title="No USER instruction — container runs as root",
            description="The final build stage never sets USER, so the container runs as "
                         "root by default. A container escape or RCE in this container "
                         "gets root inside the container (and, depending on runtime "
                         "configuration, potentially a path toward host compromise).",
            remediation='Add a non-root user and switch to it: RUN adduser -D appuser && '
                         "USER appuser (syntax varies by base image).",
        )]
    return []


def check_latest_tag(dockerfile, resource_id: str) -> list:
    findings = []
    for instr in dockerfile.all("FROM"):
        image_ref = instr.raw_args.split(" ")[0]  # strip " AS stagename" if present
        if ":" not in image_ref or image_ref.endswith(":latest"):
            findings.append(Finding(
                resource_type="dockerfile", resource_id=resource_id, rule_id="DOCKER-002",
                severity=Severity.MEDIUM,
                title=f"Base image '{image_ref}' uses 'latest' tag (or no tag at all)",
                description="Using ':latest' (or omitting a tag, which defaults to it) means "
                             "the exact image content can change between builds without "
                             "warning — breaking reproducibility and making it impossible to "
                             "know exactly what shipped.",
                remediation="Pin to a specific version tag, ideally with a digest: "
                             "FROM node:18.20.4@sha256:...",
            ))
    return findings


def check_add_instead_of_copy(dockerfile, resource_id: str) -> list:
    findings = []
    for instr in dockerfile.all("ADD"):
        if instr.raw_args.startswith("http://") or instr.raw_args.startswith("https://"):
            continue  # ADD's remote-URL-fetch behavior is its one legitimate use case
        findings.append(Finding(
            resource_type="dockerfile", resource_id=resource_id, rule_id="DOCKER-003",
            severity=Severity.LOW,
            title="ADD used where COPY would be safer",
            description=f"Line: 'ADD {instr.raw_args}'. ADD has surprising behaviors COPY "
                         "doesn't — it auto-extracts local tar archives and can fetch remote "
                         "URLs, which has led to real supply-chain surprises when someone "
                         "expected a simple file copy.",
            remediation="Use COPY unless you specifically need ADD's tar-extraction or "
                         "remote-URL behavior.",
        ))
    return findings


def check_secrets_in_env_or_arg(dockerfile, resource_id: str) -> list:
    findings = []
    for instr in dockerfile.all("ENV") + dockerfile.all("ARG"):
        if _SECRET_ENV_PATTERN.search(instr.raw_args):
            findings.append(Finding(
                resource_type="dockerfile", resource_id=resource_id, rule_id="DOCKER-004",
                severity=Severity.CRITICAL,
                title=f"Possible secret in {instr.instruction} instruction",
                description=f"Line {instr.line_number}: '{instr.instruction} {instr.raw_args}'. "
                             "ENV/ARG values are baked into image layer history — visible to "
                             "anyone with `docker history` access, even if a later layer "
                             "removes the file, and even for multi-stage builds if the ARG is "
                             "used in an early stage.",
                remediation="Use Docker secrets (BuildKit --secret flag) or inject at "
                             "runtime via an orchestrator's secret management, never ENV/ARG.",
            ))
    return findings


def check_missing_healthcheck(dockerfile, resource_id: str) -> list:
    last_stage = dockerfile.last_stage_instructions()
    has_healthcheck = any(i.instruction == "HEALTHCHECK" for i in last_stage)
    if not has_healthcheck:
        return [Finding(
            resource_type="dockerfile", resource_id=resource_id, rule_id="DOCKER-005",
            severity=Severity.INFO,
            title="No HEALTHCHECK instruction",
            description="Without a HEALTHCHECK, container orchestrators can only tell if the "
                         "process is running, not whether it's actually healthy/responsive.",
            remediation="Add a HEALTHCHECK instruction appropriate to the service "
                         "(e.g. an HTTP endpoint check).",
        )]
    return []


ALL_DOCKERFILE_RULES = [
    check_missing_user,
    check_latest_tag,
    check_add_instead_of_copy,
    check_secrets_in_env_or_arg,
    check_missing_healthcheck,
]


def run_dockerfile_rules(dockerfile, resource_id: str = "Dockerfile") -> list:
    findings = []
    for rule in ALL_DOCKERFILE_RULES:
        findings.extend(rule(dockerfile, resource_id))
    return findings
