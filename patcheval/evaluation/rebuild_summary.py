#!/usr/bin/env python3
"""
rebuild_summary.py — Tái tạo summary.json / summary_report.txt CỘNG DỒN
tất cả CVE đã evaluate, dựa trên các file log riêng trong logs/<CVE>/.

Vấn đề gốc: run_evaluation.py mỗi lần chạy chỉ ghi summary.json cho các
CVE của LẦN CHẠY ĐÓ, ghi đè lên kết quả các lần chạy trước. Nhưng file
log riêng từng CVE (success_output.log / error_output.log) thì KHÔNG bị
xoá — nên có thể quét lại toàn bộ để dựng lại summary chính xác.

Cách dùng:
    python3 rebuild_summary.py --results_dir evaluation_output/results/go_poc \
        --dataset ../datasets/patcheval_verified_go.json

Sẽ ghi đè (backup bản cũ trước):
    <results_dir>/summary.json
    <results_dir>/summary_report.txt
"""
import argparse
import json
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path


def load_cve_language_map(dataset_path):
    """Trả về dict cve_id -> programing_language, đọc từ dataset gốc."""
    if not dataset_path or not os.path.exists(dataset_path):
        return {}
    with open(dataset_path, encoding="utf-8") as f:
        data = json.load(f)
    return {d["cve_id"]: d.get("programing_language", "Unknown") for d in data}


def extract_validation_type(error_text: str) -> str:
    """Doc lai dong '[Validation TYPE]: xxx' trong error_output.log."""
    m = re.search(r"\[Validation TYPE\]:\s*(\S+)", error_text)
    if m:
        return m.group(1)
    return "unknown_fail"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results_dir", required=True,
                     help="vd: evaluation_output/results/go_poc")
    ap.add_argument("--dataset", default=None,
                     help="patcheval_verified_go.json — de lay dung ten ngon ngu")
    ap.add_argument("--default_language", default="Go",
                     help="Ngon ngu mac dinh neu khong tim thay trong dataset")
    args = ap.parse_args()

    logs_dir = Path(args.results_dir) / "logs"
    if not logs_dir.exists():
        raise SystemExit(f"Khong tim thay thu muc logs: {logs_dir}")

    lang_map = load_cve_language_map(args.dataset)

    success_summary = defaultdict(list)
    fail_summary = defaultdict(list)
    total_cases = 0

    cve_dirs = sorted([p for p in logs_dir.iterdir() if p.is_dir()])

    for cve_dir in cve_dirs:
        cve = cve_dir.name
        success_log = cve_dir / "success_output.log"
        error_log = cve_dir / "error_output.log"

        language = lang_map.get(cve, args.default_language)

        if success_log.exists():
            total_cases += 1
            success_summary[language].append(cve)
        elif error_log.exists():
            total_cases += 1
            text = error_log.read_text(encoding="utf-8", errors="replace")
            vtype = extract_validation_type(text)
            # Chuan hoa ten giong cach run_evaluation.py dat ten:
            # vd "Go_compilation_fail", "Go_validation_fail"
            if vtype == "Repair Success":
                # Truong hop hiem: co error_output.log nhung thuc ra pass
                # (khong nen xay ra, nhung phong truong hop)
                success_summary[language].append(cve)
                total_cases -= 0
            else:
                fail_summary[f"{language}_{vtype}"].append(cve)
        else:
            # Thu muc CVE ton tai nhung khong co log nao ben trong ->
            # co the bi ngat giua chung (vd het disk) -> bo qua, coi nhu
            # chua evaluate xong.
            print(f"[WARN] {cve}: khong co success/error log, bo qua (co the bi ngat giua chung).")

    # ---- Tinh toan tong hop ----
    total_success = sum(len(v) for v in success_summary.values())
    pass_rate = (total_success / total_cases * 100) if total_cases else 0

    lang_breakdown = {lang: len(cves) for lang, cves in success_summary.items()}
    fail_analysis = {key: len(cves) for key, cves in fail_summary.items()}

    # ---- summary_report.txt ----
    lines = []
    lines.append("=" * 60)
    lines.append(f"{'PoC Evaluation Summary (REBUILT - cumulative)':^60}")
    lines.append("=" * 60)
    lines.append(f"Total Cases Evaluated: {total_cases}")
    lines.append(f"Total Successful Repairs: {total_success}")
    lines.append(f"Overall Pass Rate: {pass_rate:.2f}%")
    lines.append("-" * 60)
    lines.append("Success Breakdown by Language:")
    if not lang_breakdown:
        lines.append("  None")
    else:
        for lang, count in sorted(lang_breakdown.items()):
            lines.append(f"  - {lang}: {count}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("=" * 60)
    lines.append(f"{'Failure Analysis':^60}")
    lines.append("=" * 60)
    if not fail_analysis:
        lines.append("No failures recorded.")
    else:
        for reason, count in sorted(fail_analysis.items()):
            lines.append(f"- {reason}: {count}")
    report_str = "\n".join(lines)

    # ---- summary.json ----
    full_json = {
        "poc_evaluation": {
            "title": "PoC Evaluation Summary (rebuilt cumulative)",
            "total_cases": total_cases,
            "total_success": total_success,
            "pass_rate": f"{pass_rate:.2f}%",
            "success_breakdown": lang_breakdown,
            "successful_cves": dict(success_summary),
        },
        "failure_analysis": {
            "breakdown": fail_analysis,
            "failed_cves": dict(fail_summary),
        },
        "execution_errors": [],
    }

    # ---- Backup file cu truoc khi ghi de ----
    results_dir = Path(args.results_dir)
    for fname in ("summary.json", "summary_report.txt"):
        fpath = results_dir / fname
        if fpath.exists():
            shutil.copy(fpath, results_dir / f"{fname}.bak")

    with open(results_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(full_json, f, indent=4, ensure_ascii=False)
    with open(results_dir / "summary_report.txt", "w", encoding="utf-8") as f:
        f.write(report_str)

    print(report_str)
    print(f"\n[OK] Da ghi lai (co backup .bak): {results_dir}/summary.json va summary_report.txt")


if __name__ == "__main__":
    main()
