"""CLI: build_parser and main entry point for patcheval_toolkit."""
import argparse
from toolkit.eda import cmd_eda, cmd_complexity
from toolkit.generate_python import cmd_generate
from toolkit.generate_go import cmd_go_generate
from toolkit.generate_js import cmd_js_generate
from toolkit.agent import cmd_go_agent
from toolkit.export import cmd_export
from toolkit.misc import cmd_check_bytes, cmd_extract_patch
from toolkit.utils import cmd_save_eval

def build_parser():
    ap = argparse.ArgumentParser(
        prog="patcheval_toolkit.py",
        description=(
            "PatchEval toolkit — Python EDA/generate/export "
            "+ Go patch generation (Gemini & OpenRouter) + agent mode"
        ),
    )
    sub = ap.add_subparsers(dest="command", required=True)

    # ── eda ──────────────────────────────────────────────────────────
    p_eda = sub.add_parser("eda", help="EDA for CVE dataset and evaluation results (failure analysis & metrics)")
    p_eda.add_argument("--input", required=True, help="Dataset JSON (patcheval_verified.json or language subset)")
    p_eda.add_argument("--lang", default="all", help="Language filter: all | Python | Go | JavaScript (default: all)")
    p_eda.add_argument("--eval-results", default=None, help="Companion eval_results.json or evaluation summary.json")
    p_eda.add_argument("--outdir", default="./eda", help="Output directory for EDA tables and summaries")
    p_eda.set_defaults(func=cmd_eda)

    # ── save-eval ────────────────────────────────────────────────────
    p_save_eval = sub.add_parser("save-eval", help="Save evaluation results, failure analysis (apply_fail, compilation_fail, validation_fail) & tokens to companion JSON & EDA. Also writes per-CVE pass/fail JSON files + results.json summary.")
    p_save_eval.add_argument("--patch-file", required=True, help="eval_inputs/<label>.jsonl")
    p_save_eval.add_argument("--eval-dir", required=True, help="Path to evaluation_output/results/<label> or summary.json")
    p_save_eval.add_argument("--dataset", default=None, help="Dataset JSON (patcheval_verified_go.json or patcheval_verified.json)")
    p_save_eval.add_argument("--model", default="unknown", help="Model ID (e.g. deepseek/deepseek-v4-0731) — stored in each CVE JSON")
    p_save_eval.add_argument("--language", default="unknown", help="Language label: go | javascript | python")
    p_save_eval.add_argument("--eda-dir", default="./eda", help="Directory to save EDA summaries (default: ./eda)")
    p_save_eval.set_defaults(func=cmd_save_eval)

    # ── complexity ───────────────────────────────────────────────────
    p_cx = sub.add_parser("complexity", help="Structural complexity analysis for Python (requires radon)")
    p_cx.add_argument("--input", required=True)
    p_cx.add_argument("--outdir", default="./output_python")
    p_cx.set_defaults(func=cmd_complexity)

    # ── generate (Python) ────────────────────────────────────────────
    p_gen = sub.add_parser("generate", help="Batch patch generation for Python CVEs")
    p_gen.add_argument("--input", required=True, help="patcheval_verified.json")
    p_gen.add_argument("--output", default="python_patches_gemini.jsonl")
    p_gen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_gen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                       help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_gen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_gen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_gen.add_argument("--max_tokens", type=int, default=6000)
    p_gen.set_defaults(func=cmd_generate)

    # ── py-generate (alias for generate, consistent naming with go/js) ───
    p_pygen = sub.add_parser("py-generate", help="Batch patch generation for Python CVEs (alias for 'generate')")
    p_pygen.add_argument("--input", required=True, help="patcheval_verified.json or python subset")
    p_pygen.add_argument("--output", default="python_patches.jsonl")
    p_pygen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_pygen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_pygen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_pygen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_pygen.add_argument("--max_tokens", type=int, default=6000)
    p_pygen.set_defaults(func=cmd_generate)

    # ── go-generate ──────────────────────────────────────────────────
    p_gogen = sub.add_parser("go-generate", help="Batch snippet-level patch generation for Go CVEs")
    p_gogen.add_argument("--input", required=True, help="patcheval_verified.json or go subset")
    p_gogen.add_argument("--output", default="go_patches.jsonl")
    p_gogen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_gogen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_gogen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_gogen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_gogen.add_argument("--max_tokens", type=int, default=6000)
    p_gogen.set_defaults(func=cmd_go_generate)

    # ── js-generate ──────────────────────────────────────────────────
    p_jsgen = sub.add_parser("js-generate", help="Batch snippet-level patch generation for JavaScript CVEs")
    p_jsgen.add_argument("--input", required=True, help="patcheval_verified.json or js subset")
    p_jsgen.add_argument("--output", default="js_patches.jsonl")
    p_jsgen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_jsgen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_jsgen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_jsgen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_jsgen.add_argument("--max_tokens", type=int, default=6000)
    p_jsgen.set_defaults(func=cmd_js_generate)

    # ── go-agent ─────────────────────────────────────────────────────
    p_agent = sub.add_parser("go-agent", help="Agent mode for Docker runner (replaces my_gemini_agent.py)")
    p_agent.add_argument("prompt_file", help="Path to the prompt text file written by patch_agent_runner.py")
    p_agent.add_argument("workdir", help="Repository root inside the Docker container")
    p_agent.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_agent.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model (only used when --provider openrouter)")
    p_agent.set_defaults(func=cmd_go_agent)

    # ── export ───────────────────────────────────────────────────────
    p_exp = sub.add_parser("export", help="Generate HTML/CSV analysis report + gap analysis")
    p_exp.add_argument("--dataset", required=True)
    p_exp.add_argument("--patches", nargs="+", required=True)
    p_exp.add_argument("--eval_summary", nargs="+", required=True,
                       help="One summary.json per --patches file, in the same order")
    p_exp.add_argument("--outdir", default="./report")
    p_exp.set_defaults(func=cmd_export)

    # ── check-bytes ──────────────────────────────────────────────────
    p_cb = sub.add_parser("check-bytes", help="Detect hidden \\r\\n in .jsonl files")
    p_cb.add_argument("path", nargs="?", default="go_patches.jsonl")
    p_cb.set_defaults(func=cmd_check_bytes)

    # ── extract-patch ────────────────────────────────────────────────
    p_ep = sub.add_parser("extract-patch", help="Extract a single CVE's patch to a standalone .patch file")
    p_ep.add_argument("jsonl_path")
    p_ep.add_argument("cve_id")
    p_ep.add_argument("out_path", nargs="?", default="test.patch")
    p_ep.set_defaults(func=cmd_extract_patch)

    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
