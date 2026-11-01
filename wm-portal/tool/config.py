# -*- coding: utf-8 -*-
"""全局配置（全部走环境变量，支持同目录 .env 文件，便于零成本部署）。

必填：SERVER_SECRET、DB_KEY
发信：RESEND_API_KEY + RESEND_FROM_EMAIL（或 SMTP_* 走 QQ 邮箱备选）
"""
from __future__ import annotations

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv() -> None:
    path = os.path.join(BASE_DIR, ".env")
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip("'\"")
            if k and k not in os.environ:
                os.environ[k] = v


_load_dotenv()


def _need(name: str, hint: str = "") -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        # GUI 启动时允许配置为空，由设置页引导用户生成
        if os.environ.get("WM_GUI"):
            return ""
        raise SystemExit(
            f"[配置缺失] 环境变量 {name} 未设置。{hint}\n"
            f"  方式一：写入 {os.path.join(BASE_DIR, '.env')}\n"
            f"  方式二：export {name}='...'")
    return v


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


# ============ 水印密钥（HMAC 签名，防伪造栽赃）============
SERVER_SECRET = _get("SERVER_SECRET") or _need(
    "SERVER_SECRET", "用于给水印 ID 签名，至少 32 字符：python -c \"import os;print(os.urandom(32).hex())\"")

# ============ 数据库 ============
DB_PATH = _get("DB_PATH", os.path.join(BASE_DIR, "mapping.db"))
DB_KEY = _get("DB_KEY") or _need("DB_KEY", "SQLCipher / 字段加密主密钥")

# ============ Resend 邮件（主通道）============
RESEND_API_KEY = _get("RESEND_API_KEY")
RESEND_FROM_EMAIL = _get("RESEND_FROM_EMAIL", "noreply@example.com")

# ============ SMTP 备选（QQ 邮箱授权码等）============
SMTP_HOST = _get("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = _get_int("SMTP_PORT", 465)
SMTP_USER = _get("SMTP_USER")
SMTP_PASS = _get("SMTP_PASS")          # QQ 邮箱填「授权码」而非登录密码
SMTP_FROM = _get("SMTP_FROM") or SMTP_USER

# ============ 发送频率 ============
SEND_INTERVAL = _get_float("SEND_INTERVAL", 3.0)   # Resend 限速 10 req/s，保守 3 秒
DAILY_LIMIT = _get_int("DAILY_LIMIT", 100)         # Resend 免费版日限

# 邮件发出去之后，本地 out/ 里那份成品要不要留？
#   0（默认）= 删掉：成品带水印，堆在本地是风险
#   1        = 保留：想同时用「网页领取」路线（需要上传），或者想留档对账
KEEP_LOCAL = _get_int("KEEP_LOCAL", 0)

# ============ 合规 ============
POLICY_VERSION = _get("POLICY_VERSION", "2026-10-01")

# ============ 水印通道开关与参数 ============
ZW_ENABLED = _get("ZW_ENABLED", "1") not in ("0", "false", "False")
CSS_ENABLED = _get("CSS_ENABLED", "1") not in ("0", "false", "False")
IMG_ENABLED = _get("IMG_ENABLED", "1") not in ("0", "false", "False")

# 新增的三层（六层正交体系）
ATTR_ENABLED = _get("ATTR_ENABLED", "1") not in ("0", "false", "False")   # XHTML 属性引号
OPF_ENABLED = _get("OPF_ENABLED", "1") not in ("0", "false", "False")     # OPF 条目顺序
ZIP_ENABLED = _get("ZIP_ENABLED", "1") not in ("0", "false", "False")
# 诱饵：公开密钥可检测的"清洗探针"，写在最容易被发现的层
DECOY_ENABLED = _get("DECOY_ENABLED", "1") not in ("0", "false", "False")
# 变体选择符：默认关闭 —— U+E0100 在部分字体下会显示豆腐块，中文精排书有风险
VS_ENABLED = _get("VS_ENABLED", "0") not in ("0", "false", "False")

# ---- 分布自然性（对抗"全库一致性统计"）----
# 对抗方不需要密钥：只要统计"哪几章写法不一样"就能定位水印。
# 曾经只嵌 6/94 章、每章固定 96 字符，形成"绝大多数 + 极少数"和"定额"两个
# 特征，被一眼识破。现在改成：总冗余不变，但**均匀铺到全部正文页**，
# 于是"每章都有"就不再是异常，只剩"某些字符/引号多了几个"这种无法归因的噪声。
# 0 = 铺到全部正文页；>0 = 均匀抽样这么多页（超大的书用它设上限）
ZW_SPREAD_PAGES = _get_int("ZW_SPREAD_PAGES", 0)
ATTR_SPREAD_PAGES = _get_int("ATTR_SPREAD_PAGES", 0)

ATTR_PAGES = _get_int("ATTR_PAGES", 8)        # 属性通道覆盖的正文页数（旧选项，铺开后失效）

ZW_CHARSET = _get("ZW_CHARSET", "ext8")     # safe4 / ext8 / full16
# 铺开到全部页之后，冗余由"页数"提供，每页 1 份就够（也避免每章定额）
ZW_COPIES = _get_int("ZW_COPIES", 1)        # 每个正文文件的副本数
# 属性层必须保留多副本：它把比特流铺在**跨页累积**的一条长序列上，
# 单个副本里只要有几个位置改不动（属性值本身含引号等）就会 CRC 校验失败。
# 不能跟着 ZW_COPIES 走 —— 那是为了"每章定额"才降到 1 的。
ATTR_COPIES = _get_int("ATTR_COPIES", 3)
# 1 份即可：有的书 CSS 总容量刚好等于 2 份的需求（192 bit），一点余量都没有，
# 4 次里会挂 1 次。降到 1 份留出 2 倍余量，稳定性优先于冗余。
CSS_COPIES = _get_int("CSS_COPIES", 1)
IMG_COPIES = _get_int("IMG_COPIES", 7)
MAX_XHTML = _get_int("MAX_XHTML", 6)        # 文本通道覆盖的章节数

# 图片通道：给整本书的插图都嵌（封面 + 正文插图按文档顺序均匀采样），
# 这样换掉封面、删掉几章都还能解出来。数量越大越慢，一般 8~20 足够。
MAX_IMAGES = _get_int("MAX_IMAGES", 8)
IMG_MIN_BYTES = _get_int("IMG_MIN_BYTES", 6 * 1024)      # 太小的图（图标/装饰）跳过
IMG_MIN_PIXELS = _get_int("IMG_MIN_PIXELS", 128)          # 短边下限
IMG_MAX_PIXELS = _get_int("IMG_MAX_PIXELS", 2600 * 2600)  # 超大图跳过，避免耗时陡增
JPEG_QUALITY = _get_int("JPEG_QUALITY", 95)

# 图片 QIM
DELTA = _get_float("DELTA", 32.0)           # QIM 量化步长（JPEG 容器）
DELTA_PNG = _get_float("DELTA_PNG", 16.0)   # PNG 无损容器可用更小的步长
PSNR_THRESHOLD = _get_float("PSNR_THRESHOLD", 30.0)
MAX_EMBED_ITER = _get_int("MAX_EMBED_ITER", 3)

# ============ 本地管理后台 ============
ADMIN_HOST = _get("ADMIN_HOST", "127.0.0.1")
ADMIN_PORT = _get_int("ADMIN_PORT", 8765)
ADMIN_PASSWORD = _get("ADMIN_PASSWORD")   # 留空则每次启动随机生成并打印

# 输出目录
# 本地成品命名：full=带完整水印ID（默认） / short=只带后4位 / clean=纯序号
FILENAME_MODE = _get("FILENAME_MODE", "full").strip().lower()
OUTPUT_DIR = _get("OUTPUT_DIR", os.path.join(BASE_DIR, "out"))
BACKUP_DIR = _get("BACKUP_DIR", os.path.join(BASE_DIR, "backups"))
