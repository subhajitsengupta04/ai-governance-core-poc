import json
import os
import re
import subprocess
import sys
from pathlib import Path
import yaml
from jsonschema import validate, ValidationError

AI_KEYWORDS = ("openai", "langchain", "anthropic", "azure.ai", "ollama", "transformers", "llama_index")
MANIFEST_PATH = Path("ai-manifest.yaml")
SCHEMA_PATH = Path("governance/ai-manifest.schema.json")
COMMENT_OUTPUT = Path("pr_comment.md")


def run_git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def get_changed_files(base_ref: str) -> list[str]:
    output = run_git(["diff", "--name-only", f"origin/{base_ref}...HEAD"])
    return [line.strip() for line in output.splitlines() if line.strip()]


def detect_ai_changes(base_ref: str, changed_files: list[str]) -> tuple[bool, bool]:
    ai_touched = False
    prompts_touched = False

    for file_path in changed_files:
        if file_path == str(MANIFEST_PATH):
            ai_touched = True
        if file_path.startswith("prompts/"):
            ai_touched = True
            prompts_touched = True

    diff_text = run_git(["diff", f"origin/{base_ref}...HEAD"])
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            if any(kw in line.lower() for kw in AI_KEYWORDS):
                ai_touched = True

    return ai_touched, prompts_touched


def write_comment(body: str) -> None:
    COMMENT_OUTPUT.write_text(body, encoding="utf-8")


def main() -> int:
    base_ref = os.getenv("GITHUB_BASE_REF", "main")
    pr_labels = json.loads(os.getenv("PR_LABELS_JSON", "[]"))

    if "governance-override" in pr_labels:
        write_comment(
            "### AI Governance: Break-Glass Override Active\n"
            "Merge unblocked via `governance-override` label. **A 48-hour InfoSec audit ticket will be triggered automatically.**"
        )
        print("Break-glass override detected. Passing check.")
        return 0

    changed_files = get_changed_files(base_ref)
    ai_touched, prompts_touched = detect_ai_changes(base_ref, changed_files)

    if not ai_touched:
        write_comment(
            "### AI Governance Check: Skipped\n"
            "No AI libraries, `/prompts/`, or `ai-manifest.yaml` changes detected in this PR."
        )
        print("No AI changes detected. Skipping governance check.")
        return 0

    if not MANIFEST_PATH.exists():
        write_comment(
            "### AI Governance Check Failed: Missing `ai-manifest.yaml`\n"
            "This PR modifies AI dependencies or prompts, but no `ai-manifest.yaml` was found.\n\n"
            "**How to fix in 30 seconds:**\n"
            "```bash\npython governance/init_ai_label.py\ngit add ai-manifest.yaml && git commit -m 'Add AI nutrition label'\n```"
        )
        print("ERROR: ai-manifest.yaml is missing.", file=sys.stderr)
        return 1

    try:
        manifest_data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
        schema_data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validate(instance=manifest_data, schema=schema_data)
    except (yaml.YAMLError, ValidationError) as exc:
        msg = exc.message if isinstance(exc, ValidationError) else str(exc)
        write_comment(
            f"### AI Governance Check Failed: Invalid `ai-manifest.yaml`\n"
            f"**Validation Error:** `{msg}`\n\n"
            f"Run `python governance/init_ai_label.py` to regenerate a schema-compliant manifest."
        )
        print(f"Schema validation error: {msg}", file=sys.stderr)
        return 1

    # Check for stale evaluation commit when prompts/ are modified
    if prompts_touched:
        head_sha = run_git(["rev-parse", "--short", "HEAD"])
        eval_sha = manifest_data["safety_and_controls"]["last_eval_commit"]
        if str(MANIFEST_PATH) not in changed_files or not re.match(r"^[a-fA-F0-9]{7,40}$", eval_sha):
            write_comment(
                "### AI Governance Check Failed: Stale Prompt Evaluation\n"
                "Files inside `prompts/` were modified, but `safety_and_controls.last_eval_commit` in `ai-manifest.yaml` was not updated.\n\n"
                f"Run your evaluation suite and update `last_eval_commit` (e.g., `{head_sha}`) before merging."
            )
            print("ERROR: Prompts changed without updating last_eval_commit.", file=sys.stderr)
            return 1

    # Risk routing evaluation
    risk_tier = manifest_data["risk_tier"]
    data_class = manifest_data["data_governance"]["max_data_classification"]
    egress = manifest_data["data_governance"]["external_data_egress"]
    high_risk = (
        risk_tier in ("tier-3-customer-facing", "tier-4-autonomous-action")
        or data_class == "restricted-pii"
        or egress is True
    )

    routing_badge = (
        " **High-Risk Escalation:** Security/Legal review required (`@ericsson/infosec-reviewers`)"
        if high_risk
        else " **Standard Peer Review:** Low/Moderate risk profile — ready for engineering merge"
    )

    summary_md = f"""### AI Nutrition Label Summary
{routing_badge}

| Attribute | Declared Value |
| :--- | :--- |
| **System Name** | `{manifest_data['system_name']}` |
| **Owner Team** | `{manifest_data['owner_team']}` |
| **Risk Tier** | `{risk_tier}` |
| **Model** | `{manifest_data['model_supply_chain']['provider']} / {manifest_data['model_supply_chain']['model_id']}` |
| **Data Classification** | `{data_class}` (External Egress: `{egress}`) |
| **Human-in-the-Loop** | `{manifest_data['safety_and_controls']['human_in_the_loop']}` |
| **Last Eval Commit** | `{manifest_data['safety_and_controls']['last_eval_commit']}` |
"""
    write_comment(summary_md)
    print("AI Nutrition Label validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())