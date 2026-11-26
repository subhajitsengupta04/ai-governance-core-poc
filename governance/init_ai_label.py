import subprocess
from pathlib import Path
import yaml
import re


ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def clean_input(prompt: str) -> str:
    raw = input(prompt)
    return ANSI_ESCAPE.sub("", raw).strip()

def prompt_choice(question: str, options: list[str]) -> str:
    print(f"\n{question}")
    for idx, opt in enumerate(options, 1):
        print(f"  {idx}. {opt}")
    while True:
        choice = input("Select option number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid selection. Try again.")


def get_latest_commit() -> str:
    try:
        res = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "a1b2c3d"


def main() -> None:
    print("=== AI Nutrition Label Generator ===")
    system_name = input("1. System name (e.g., ticket-triage-bot): ").strip() or "demo-ai-service"
    owner_team = input("2. Owner team handle (e.g., @ai-platform): ").strip() or "@ai-platform"
    if not owner_team.startswith("@"):
        owner_team = f"@{owner_team}"

    risk_tier = prompt_choice(
        "3. Select Risk Tier:",
        ["tier-1-sandbox", "tier-2-internal-assist", "tier-3-customer-facing", "tier-4-autonomous-action"],
    )
    provider = prompt_choice(
        "4. Select Model Provider:",
        ["azure-openai", "aws-bedrock", "local-ollama", "openai", "anthropic", "huggingface"],
    )
    model_id = input("   Model ID (e.g., gpt-4o, llama3.1): ").strip() or "gpt-4o"

    data_class = prompt_choice(
        "5. Max Data Classification:",
        ["public", "internal", "confidential", "restricted-pii"],
    )
    hitl = prompt_choice(
        "6. Human-in-the-Loop Control:",
        ["none", "async-audit", "required-before-action"],
    )

    manifest = {
        "schema_version": "1.0",
        "system_name": system_name,
        "owner_team": owner_team,
        "risk_tier": risk_tier,
        "model_supply_chain": {
            "provider": provider,
            "model_id": model_id,
            "fine_tuned": False,
        },
        "data_governance": {
            "max_data_classification": data_class,
            "rag_sources": ["internal-knowledge-base"],
            "external_data_egress": data_class == "restricted-pii",
        },
        "safety_and_controls": {
            "human_in_the_loop": hitl,
            "fallback_behavior": "graceful-error-message",
            "prompt_injection_guard": "system-delimiter-check",
            "last_eval_commit": get_latest_commit(),
        },
    }

    Path("ai-manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    print("\n Generated ai-manifest.yaml successfully!")


if __name__ == "__main__":
    main()