# Gemini / OpenRouter agent adapter. Source this file from run_infer.sh.

AGENT_MOUNTS=()
AGENT_EXTRA_ARGS=()
AGENT_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/patcheval_toolkit.py"

AGENT_MOUNTS+=("${AGENT_SCRIPT}:/opt/patcheval_toolkit.py:ro")
AGENT_COMMAND="GEMINI_API_KEY='${GEMINI_API_KEY:-}' OPENROUTER_API_KEY='${OPENROUTER_API_KEY:-}' GEMINI_MODEL='${GEMINI_MODEL:-gemini-2.0-flash}' python3 /opt/patcheval_toolkit.py go-agent {prompt_file} {workdir} --provider ${API_PROVIDER:-gemini}"
