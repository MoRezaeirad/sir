#!/usr/bin/env bash
# One-command AgentDojo run for the sir defense.
#
# It (1) builds sir, (2) runs the offline self-test (no network/key), (3) creates
# a throwaway venv and installs agentdojo + the provider SDK, then (4) runs the
# benchmark with sir mediation and writes scores to ../results/.
#
# Usage:
#   export OPENAI_API_KEY=sk-...           # or ANTHROPIC_API_KEY for --provider anthropic
#   eval/agentdojo/run.sh                                  # defaults: openai / gpt-4o / all suites, with baseline
#   PROVIDER=anthropic MODEL=claude-3-5-sonnet-latest eval/agentdojo/run.sh
#   SUITES="workspace banking" eval/agentdojo/run.sh       # subset of suites
#
# Env knobs: PROVIDER (openai|anthropic), MODEL, SUITES, ATTACK, BASELINE (1/0).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

PROVIDER="${PROVIDER:-openai}"
MODEL="${MODEL:-gpt-4o}"
SUITES="${SUITES:-workspace banking slack travel}"
ATTACK="${ATTACK:-important_instructions}"
BASELINE="${BASELINE:-1}"

echo "==> [1/4] Building sir (so the bridge talks to the real decision path)"
go -C "$REPO_ROOT" build -o "$HERE/.sir-bin" ./cmd/sir
export SIR_BIN="$HERE/.sir-bin"

echo "==> [2/4] Offline self-test (Go only — proves the wiring before spending tokens)"
python3 "$HERE/selftest.py"

echo "==> [3/4] Python venv + agentdojo + ${PROVIDER} SDK"
VENV="$HERE/.venv"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet agentdojo
if [ "$PROVIDER" = "openai" ]; then
  pip install --quiet "openai>=1.40"
  : "${OPENAI_API_KEY:?set OPENAI_API_KEY for --provider openai}"
else
  pip install --quiet "anthropic>=0.40"
  : "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY for --provider anthropic}"
fi

echo "==> [4/4] Running AgentDojo with sir mediation (provider=$PROVIDER model=$MODEL)"
ARGS=(--provider "$PROVIDER" --model "$MODEL" --attack "$ATTACK" --suites $SUITES)
if [ "$BASELINE" = "1" ]; then ARGS+=(--baseline); fi
python3 "$HERE/run.py" "${ARGS[@]}"

echo
echo "Done. Scores written under: $REPO_ROOT/eval/results/"
echo "Read targeted_asr (want ~0 with sir) and utility (the over-block signal, want >0.80)."
