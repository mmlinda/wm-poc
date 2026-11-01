#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""job_to_env.py —— 把 Worker 领到的任务转换成 runner 上的两个文件。

为什么要单独一个脚本（而不是在 workflow 里写 heredoc）：
    GitHub Actions 的 `run: |` 是 YAML 块标量，**块里的每一行都必须缩进**。
    之前为了图省事在块里贴了顶格（第 0 列）的 `python - <<'PY' ... PY`，
    整个文件就不是合法 YAML 了 —— 于是 dispatch 报 422
    "Workflow does not have 'workflow_dispatch' trigger"，查了两轮才发现。
    正确做法：把逻辑放进仓库里的脚本，YAML 只负责调用。

用法（在 workflow 的 shell 里）：
    python poc/job_to_env.py job.json >> "$GITHUB_ENV"

做的事：
    1) 写 qq.csv（UTF-8 BOM，引擎按 BOM 识别中文列名）
    2) 把 MOTHER_URL / UPLOAD_URL / SERVER_SECRET / DB_KEY 以 KEY=VALUE 打到 stdout，
       由 workflow 重定向进 $GITHUB_ENV —— 这样不会出现在日志里（密钥不打屏）
    3) 缺字段直接非零退出（宁可这一步红，也不要在跑引擎时才发现少东西）
"""
import csv
import json
import os
import sys

REQUIRED = ("qqs", "mother_url", "upload_url", "creds")


def fail(msg):
    sys.stderr.write("job_to_env: %s\n" % msg)
    raise SystemExit(2)


def main(argv):
    path = argv[1] if len(argv) > 1 else "job.json"
    if not os.path.isfile(path):
        fail("找不到 %s" % path)
    try:
        j = json.load(open(path, encoding="utf-8"))
    except Exception as e:                                   # noqa: BLE001
        fail("%s 不是合法 JSON：%s" % (path, e))

    missing = [k for k in REQUIRED if not j.get(k)]
    if missing:
        fail("job.json 缺字段：%s（完整内容已打到上面，检查 Worker 返回）" % ", ".join(missing))

    qqs = [str(q).strip() for q in j["qqs"] if str(q).strip()]
    if not qqs:
        fail("qqs 是空数组 —— 名单为空或都处于 banned 状态")

    # 引擎的 CSV 读取按 utf-8-sig 解析列名，这里保持一致
    with open("qq.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["qq_number", "email"])
        for q in qqs:
            w.writerow([q, "%s@qq.com" % q])

    creds = j.get("creds") or {}
    for k, v in (("MOTHER_URL", j["mother_url"]),
                 ("UPLOAD_URL", j["upload_url"]),
                 ("SERVER_SECRET", creds.get("server_secret", "")),
                 ("DB_KEY", creds.get("db_key", ""))):
        if v:
            # 单行、无换行，避免污染 $GITHUB_ENV
            print("%s=%s" % (k, str(v).replace("\n", "")))

    sys.stderr.write("job_to_env: %d 个收件人，已写 qq.csv\n" % len(qqs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
