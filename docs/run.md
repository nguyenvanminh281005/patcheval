  Đây là hướng dẫn đầy đủ để chạy thực nghiệm với dataset Go trên PatchEval.
  ──────
  ## Tóm tắt nhanh
  Trong patcheval_verified.json có 83 CVE viết bằng Go (trên tổng 230 CVE). Luồng thực nghiệm gồm 4 bước chính:

  ### Bước 1 — Tạo Go subset

    python3 -c "
    import json
    with open('patcheval/datasets/patcheval_verified.json') as f: data = json.load(f)
    go = [d for d in data if d.get('programing_language','').lower() == 'go']
    with open('patcheval/datasets/patcheval_verified_go.json','w') as f: json.dump(go, f, indent=2)
    print(f'Go cases: {len(go)}')  # → 83
    "
    
  ### Bước 2 — Sinh patch (chọn 1 trong 3 agent)

    cd patcheval/exp_agent

    # Smoke test (1 CVE)
    DATASET=../datasets/patcheval_verified_go.json \
    LIMIT=1 CONCURRENCY=1 bash run_infer.sh codex go_smoke

    # Full run (83 CVE)
    DATASET=../datasets/patcheval_verified_go.json \
    CONCURRENCY=8 bash run_infer.sh codex go_full

  │ Biến DATASET ghi đè đường dẫn mặc định → chạy riêng Go mà không sửa code gốc.

  ### Bước 3 — Đánh giá

    DATASET=../datasets/patcheval_verified_go.json \
    MAX_WORKERS=4 bash run_eval.sh go_full

  ### Bước 4 — Xem kết quả

    cat patcheval/evaluation/evaluation_output/results/go_full/summary_report.txt
    ──────
  Lưu ý: Bạn cần cài đặt biến môi trường cho agent (CODEX_BIN, CODEX_CONFIG cho Codex; OPENCODE_BIN/OPENCODE_CONFIG cho OpenCode; TRAE_BIN/TRAE_CONFIG cho TraeCLI). Chi
  tiết đầy đủ kèm danh sách 83 CVE Go trong artifact go_experiment_guide.md.


hãy đọc dữ liệu trên và hướng tôi thực hiện trên ubuntu, mỗi lần pull chỉ pull thử 3 images thôi nha