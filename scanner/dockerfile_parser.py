"""
Parses a Dockerfile into a list of (instruction, arguments) tuples, plus
convenience accessors for the rules to use. Dockerfile syntax is
line-based and much simpler than HCL (no nested blocks), but still has
real edge cases handled here: line continuations with a trailing
backslash, comments, and multiple stages (multi-stage builds using
"FROM ... AS name").
"""
import re
from dataclasses import dataclass, field


@dataclass
class DockerfileInstruction:
    instruction: str  # normalized uppercase, e.g. "RUN", "USER", "FROM"
    raw_args: str
    line_number: int


@dataclass
class ParsedDockerfile:
    instructions: list = field(default_factory=list)

    def all(self, instruction: str) -> list:
        return [i for i in self.instructions if i.instruction == instruction.upper()]

    def has(self, instruction: str) -> bool:
        return len(self.all(instruction)) > 0

    def last_stage_instructions(self) -> list:
        """
        For multi-stage builds, security-relevant checks (USER, missing
        HEALTHCHECK, etc.) should generally apply to the FINAL stage,
        since that's what actually ships as the runtime image — earlier
        build stages commonly run as root deliberately (e.g. installing
        build dependencies) and that's not a security issue if they're
        discarded before the final image.
        """
        from_indices = [i for i, instr in enumerate(self.instructions) if instr.instruction == "FROM"]
        if not from_indices:
            return self.instructions
        last_from_index = from_indices[-1]
        return self.instructions[last_from_index:]


def _join_continuations(text: str) -> list:
    """Joins backslash-continued lines into single logical lines."""
    raw_lines = text.split("\n")
    joined = []
    buffer = ""
    for line in raw_lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
        else:
            buffer += line
            joined.append(buffer)
            buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


_INSTRUCTION_PATTERN = re.compile(r"^\s*([A-Za-z]+)\s+(.*)$")


def parse_dockerfile(text: str) -> ParsedDockerfile:
    parsed = ParsedDockerfile()
    logical_lines = _join_continuations(text)

    for line_number, line in enumerate(logical_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _INSTRUCTION_PATTERN.match(stripped)
        if not match:
            continue
        instruction, args = match.groups()
        parsed.instructions.append(DockerfileInstruction(
            instruction=instruction.upper(), raw_args=args.strip(), line_number=line_number,
        ))
    return parsed
