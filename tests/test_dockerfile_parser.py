import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.dockerfile_parser import parse_dockerfile


class TestBasicParsing:
    def test_parses_simple_instructions(self):
        parsed = parse_dockerfile("FROM node:18\nUSER appuser\n")
        assert len(parsed.instructions) == 2
        assert parsed.instructions[0].instruction == "FROM"
        assert parsed.instructions[1].instruction == "USER"

    def test_ignores_comments_and_blank_lines(self):
        parsed = parse_dockerfile("# comment\n\nFROM node:18\n")
        assert len(parsed.instructions) == 1

    def test_normalizes_instruction_case(self):
        parsed = parse_dockerfile("from node:18\n")
        assert parsed.instructions[0].instruction == "FROM"

    def test_has_and_all_helpers(self):
        parsed = parse_dockerfile("FROM node:18\nENV A=1\nENV B=2\n")
        assert parsed.has("ENV") is True
        assert parsed.has("USER") is False
        assert len(parsed.all("ENV")) == 2


class TestLineContinuations:
    def test_joins_backslash_continued_lines(self):
        parsed = parse_dockerfile("RUN apt-get update \\\n    && apt-get install -y curl\n")
        assert len(parsed.instructions) == 1
        assert "apt-get install" in parsed.instructions[0].raw_args


class TestMultiStage:
    def test_last_stage_instructions_returns_only_final_stage(self):
        dockerfile = """FROM node:18 AS builder
RUN npm run build
FROM node:18
COPY --from=builder /app /app
USER appuser
"""
        parsed = parse_dockerfile(dockerfile)
        last_stage = parsed.last_stage_instructions()
        instructions = [i.instruction for i in last_stage]
        assert instructions == ["FROM", "COPY", "USER"]
        assert "RUN" not in instructions  # the builder stage's RUN must be excluded

    def test_single_stage_returns_everything(self):
        parsed = parse_dockerfile("FROM node:18\nUSER appuser\n")
        assert len(parsed.last_stage_instructions()) == 2

    def test_no_from_returns_all_instructions_without_crashing(self):
        parsed = parse_dockerfile("RUN echo hello\n")
        assert len(parsed.last_stage_instructions()) == 1
