import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
import yaml
from jsonschema import validate, ValidationError

AI_KEYWORDS = (
    "openai",
    "langchain",
    "anthropic",
    "azure.ai",
    "ollama",
    "transformers",
    "llama_index",
)
MANIFEST_PATH = Path("ai-manifest.yaml")
SCHEMA_PATH = Path("/governance/ai-manifest.schema.json")
COMMENT_OUTPUT = Path("pr_comment.md")

# 1. Hardcoded AI & Cloud API Key Patterns
SECRET_PATTERNS = {
    "OpenAI API Key": re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b"),
    "Anthropic API Key": re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"),
    "Hugging Face Token": re.compile(r"\bhf_[a-zA-Z0-9]{20,}\b"),
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
}

# 2. External Public LLM Endpoints (Egress Detection)
EXTERNAL_ENDPOINT_PATTERNS = {
    "OpenAI Public API": re.compile(r"api\.openai\.com", re.IGNORECASE),
    "Anthropic Public API": re.compile(r"api\.anthropic\.com", re.IGNORECASE),
    "Google Gemini Public API": re.compile(r"generativelanguage\.googleapis\.com", re.IGNORECASE),
    "Cohere Public API": re.compile(r"api\.cohere\.ai", re.IGNORECASE),
    "Hugging Face Inference API": re.compile(r"api-inference\.huggingface\.co", re.IGNORECASE),
}

# 3. SDK Import to Declared Provider Mapping
PROVIDER_IMPORT_MAP = {
    "openai": "openai",
    "anthropic": "anthropic",
    "azure.ai": "azure-openai",
    "boto3": "aws-bedrock",
    "ollama": "local-ollama",
}

LLM_CALL_METHODS = ("create", "invoke", "generate", "run")


def run_git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def get_changed_files(base_ref: str) -> list[str]:
    output = run_git(["diff", "--name-only", f"origin/{base_ref}...HEAD"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def get_added_lines(base_ref: str) -> list[tuple[str, str]]:
    """Returns a list of (file_path, added_line_content) from the PR diff."""
    diff_text = run_git(["diff", "-U0", f"origin/{base_ref}...HEAD"])
    added = []
    current_file = "unknown"
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
        elif line.startswith("+") and not line.startswith("+++"):
            added.append((current_file, line[1:]))
    return added


def scan_diff_security_and_egress(added_lines: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """Scans added diff lines for hardcoded secrets and external LLM endpoints."""
    secret_hits = []
    external_url_hits = []

    for file_path, content in added_lines:
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                secret_hits.append(f"**{label}** detected in `{file_path}`")
        for label, pattern in EXTERNAL_ENDPOINT_PATTERNS.items():
            if pattern.search(content):
                external_url_hits.append(f"**{label}** URL detected in `{file_path}`")

    return secret_hits, external_url_hits


def _contains_llm_call(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            if child.func.attr in LLM_CALL_METHODS:
                return True
    return False


def _detect_infinite_llm_loops(tree: ast.AST, py_file: Path) -> list[str]:
    """Detects unbounded while loops or unguarded recursion containing LLM calls."""
    loop_violations = []

    for node in ast.walk(tree):
        # 1. Check while loops containing LLM calls
        if isinstance(node, ast.While) and _contains_llm_call(node):
            is_while_true = isinstance(node.test, ast.Constant) and bool(node.test.value)
            has_exit = any(isinstance(c, (ast.Break, ast.Return)) for c in ast.walk(node))
            has_bound_check = any(isinstance(c, ast.Compare) for c in ast.walk(node.test))

            if is_while_true and not has_exit:
                loop_violations.append(
                    f"**Infinite Agent Loop Risk:** `while True` containing an LLM call with no `break`/`return` at `{py_file}:{node.lineno}`."
                )
            elif not is_while_true and not has_bound_check and not has_exit:
                loop_violations.append(
                    f"**Unbounded Agent Loop Risk:** `while` loop containing an LLM call lacks a max-iteration bound (`<` / `<=`) or `break` at `{py_file}:{node.lineno}`."
                )

        # 2. Check recursive functions containing LLM calls without a depth/attempt guard
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _contains_llm_call(node):
            calls_self = any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == node.name
                for c in ast.walk(node)
            )
            has_guard_param = any(
                arg.arg in ("depth", "max_depth", "retries", "max_retries", "attempt", "step")
                for arg in node.args.args
            )
            if calls_self and not has_guard_param:
                loop_violations.append(
                    f"**Unbounded Recursion Risk:** Recursive AI function `{node.name}()` lacks a `depth` or `retries` limit parameter at `{py_file}:{node.lineno}`."
                )

    return loop_violations


def inspect_python_ast(manifest_data: dict) -> list[str]:
    """Parses Python files across the workspace to catch provider lies, unbounded calls, and infinite loops."""
    violations = []
    declared_provider = manifest_data["model_supply_chain"]["provider"]
    detected_providers = set()
    llm_calls_without_limits = []

    py_files = [
        p for p in Path(".").rglob("*.py")
        if not any(part.startswith(".") or part in ("venv", "__pycache__") for part in p.parts)
    ]

    for py_file in py_files:
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except SyntaxError:
            continue

        # Check for infinite / unbounded agent loops
        violations.extend(_detect_infinite_llm_loops(tree, py_file))

        for node in ast.walk(tree):
            # Check imports against declared provider
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for prefix, prov in PROVIDER_IMPORT_MAP.items():
                        if alias.name.startswith(prefix):
                            detected_providers.add(prov)
            elif isinstance(node, ast.ImportFrom) and node.module:
                for prefix, prov in PROVIDER_IMPORT_MAP.items():
                    if node.module.startswith(prefix):
                        detected_providers.add(prov)

            # Check LLM completion calls for missing max_tokens / timeout guardrails
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("create", "invoke", "generate"):
                    kw_names = {kw.arg for kw in node.keywords if kw.arg}
                    if not ({"max_tokens", "max_output_tokens", "timeout"} & kw_names):
                        llm_calls_without_limits.append(f"`{py_file}:{node.lineno}` (`{node.func.attr}()`)")

    # Allow azure-openai when importing openai SDK (Azure uses the openai Python package)
    compatible_providers = set(detected_providers)
    if "openai" in detected_providers:
        compatible_providers.add("azure-openai")

    if detected_providers and declared_provider not in compatible_providers:
        violations.append(
            f"**Provider Mismatch:** Code imports SDK(s) for `{', '.join(sorted(detected_providers))}`, "
            f"but `ai-manifest.yaml` declares `{declared_provider}`."
        )

    if llm_calls_without_limits:
        violations.append(
            f"**Unbounded Token/Timeout Risk:** LLM call(s) missing `max_tokens` or `timeout` guardrail at "
            f"{', '.join(llm_calls_without_limits)}."
        )

    return violations


def write_comment(body: str) -> None:
    COMMENT_OUTPUT.write_text(body, encoding="utf-8")


def set_github_output(key: str, value: str) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


def main() -> int:
    base_ref = os.getenv("GITHUB_BASE_REF", "main")
    pr_labels = json.loads(os.getenv("PR_LABELS_JSON", "[]"))
    changed_files = get_changed_files(base_ref)
    added_lines = get_added_lines(base_ref)

    # Always run secret scanning on every PR (even non-AI PRs)
    secret_hits, external_url_hits = scan_diff_security_and_egress(added_lines)
    if secret_hits:
        details = "\n".join(f"- {item}" for item in secret_hits)
        write_comment(
            "### AI Security Gatekeeper: Hardcoded API Key Blocked\n"
            "Merge blocked immediately due to exposed credentials in the PR diff:\n"
            f"{details}\n\n"
            "**Remediation:** Rotate the exposed key immediately and load it via environment variables (`os.environ`)."
        )
        print("CRITICAL: Hardcoded secret detected.", file=sys.stderr)
        return 1

    if "governance-override" in pr_labels:
        write_comment(
            "### AI Governance: Break-Glass Override Active\n"
            "Merge unblocked via `governance-override` label. **A 48-hour InfoSec audit ticket will be triggered automatically.**"
        )
        return 0

    ai_touched = any(
        f == str(MANIFEST_PATH) or f.startswith("prompts/") for f in changed_files
    ) or any(
        any(kw in content.lower() for kw in AI_KEYWORDS)
        for _, content in added_lines
    )
    prompts_touched = any(f.startswith("prompts/") for f in changed_files)

    if not ai_touched:
        write_comment(
            "### AI Governance Check: Skipped\n"
            "No AI libraries, `/prompts/`, or `ai-manifest.yaml` changes detected (secret scan passed)."
        )
        return 0

    if not MANIFEST_PATH.exists():
        write_comment(
            "### AI Governance Check Failed: Missing `ai-manifest.yaml`\n"
            "This PR introduces AI dependencies or prompts without an AI Nutrition Label.\n\n"
            "**Fix in 30 seconds:** Run `python governance/init_ai_label.py` and commit `ai-manifest.yaml`."
        )
        return 1

    try:
        manifest_data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
        schema_data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validate(instance=manifest_data, schema=schema_data)
    except (yaml.YAMLError, ValidationError) as exc:
        msg = exc.message if isinstance(exc, ValidationError) else str(exc)
        write_comment(f"### AI Governance Check Failed: Invalid `ai-manifest.yaml`\n**Schema Error:** `{msg}`")
        return 1

    # Aggregate all semantic, policy, and static-analysis violations
    violations = []

    # Check 1: Stale Prompt Evaluation
    if prompts_touched:
        head_sha = run_git(["rev-parse", "--short", "HEAD"])
        eval_sha = manifest_data["safety_and_controls"]["last_eval_commit"]
        if str(MANIFEST_PATH) not in changed_files or not re.match(r"^[a-fA-F0-9]{7,40}$", eval_sha):
            violations.append(
                f"**Stale Prompt Evaluation:** `prompts/` modified without updating `last_eval_commit` (current HEAD: `{head_sha}`)."
            )

    # Check 2: Undeclared External Data Egress
    egress_declared = manifest_data["data_governance"]["external_data_egress"]
    if external_url_hits and not egress_declared:
        violations.append(
            "**Undeclared External Egress:** `external_data_egress` is set to `false`, but code references public API endpoints: "
            + "; ".join(external_url_hits)
        )

    # Check 3: High-Risk Systems Missing Guardrails
    risk_tier = manifest_data["risk_tier"]
    hitl = manifest_data["safety_and_controls"]["human_in_the_loop"]
    guard = manifest_data["safety_and_controls"]["prompt_injection_guard"].lower()
    if risk_tier in ("tier-3-customer-facing", "tier-4-autonomous-action"):
        if hitl == "none":
            violations.append(
                f"**Unsafe Autonomy:** `{risk_tier}` systems cannot set `human_in_the_loop: none` without an InfoSec exception."
            )
        if guard in ("none", "n/a", "false", ""):
            violations.append(
                f"**Missing Injection Defense:** `{risk_tier}` systems require a valid `prompt_injection_guard`."
            )

    # Check 4: AST Static Analysis (Infinite Loops, Provider Lies & Unbounded Token Calls)
    violations.extend(inspect_python_ast(manifest_data))

    if violations:
        bullet_list = "\n".join(f"- {v}" for v in violations)
        write_comment(
            "### AI Governance & Risk Gatekeeper Failed\n"
            "The following policy or static-analysis violations must be resolved before merging:\n\n"
            f"{bullet_list}"
        )
        print("Governance check failed with violations.", file=sys.stderr)
        return 1

    data_class = manifest_data["data_governance"]["max_data_classification"]
    high_risk = (
        risk_tier in ("tier-3-customer-facing", "tier-4-autonomous-action")
        or data_class == "restricted-pii"
        or egress_declared is True
    )
    set_github_output("high_risk", "true" if high_risk else "false")

    routing_badge = (
        " **High-Risk Escalation:** Security/Legal review required (`@infosec-reviewers`)"
        if high_risk
        else " **Standard Peer Review:** Low/Moderate risk profile — ready for engineering merge"
    )

    summary_md = f"""### AI Nutrition Label Summary (All Static & Policy Checks Passed)
{routing_badge}

| Attribute | Declared Value |
| :--- | :--- |
| **System Name** | `{manifest_data['system_name']}` |
| **Owner Team** | `{manifest_data['owner_team']}` |
| **Risk Tier** | `{risk_tier}` |
| **Model** | `{manifest_data['model_supply_chain']['provider']} / {manifest_data['model_supply_chain']['model_id']}` |
| **Data Classification** | `{data_class}` (External Egress: `{egress_declared}`) |
| **Human-in-the-Loop** | `{hitl}` |
| **Prompt Injection Guard** | `{manifest_data['safety_and_controls']['prompt_injection_guard']}` |
| **Last Eval Commit** | `{manifest_data['safety_and_controls']['last_eval_commit']}` |
"""
    write_comment(summary_md)
    print("All AI governance and static checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())