"""EPUB 保真读写。

设计取舍：**不使用 ebooklib 重写整书**。ebooklib 会按自己的模板重新序列化
OPF/XHTML，容易破坏中文精排版（内联样式、注释、ruby、自定义属性等）。
这里直接在 zip 层面原地替换条目，其余字节原封不动，母本排版 0 损失。
"""
from __future__ import annotations

import io
import os
import posixpath
import re
import zipfile
import xml.etree.ElementTree as ET

NS = {
    "opf": "http://www.idpf.org/2007/opf",
    "dc": "http://purl.org/dc/elements/1.1/",
    "container": "urn:oasis:names:tc:opendocument:xmlns:container",
}

XHTML_TYPES = ("application/xhtml+xml", "text/html", "application/x-dtbook+xml")
IMAGE_TYPES = ("image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml")

# EPUB 规范：mimetype 必须位于归档首位且不压缩
MIMETYPE = "application/epub+zip"


def _decode(data: bytes) -> tuple[str, str]:
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8"


class EpubWork:
    def __init__(self, path: str):
        self.path = path
        self.zf = zipfile.ZipFile(path, "r")
        self.entries: dict[str, zipfile.ZipInfo] = {i.filename: i for i in self.zf.infolist()}
        self._modified: dict[str, bytes] = {}
        self._deleted: set[str] = set()
        self.opf_path = self._locate_opf()
        self.opf_dir = posixpath.dirname(self.opf_path)
        self._opf_bytes = self.read_raw(self.opf_path)
        self.opf_text, self.opf_enc = _decode(self._opf_bytes)
        self._parse_opf()

    # ------------------------------------------------------------ 基础 IO
    def read_raw(self, name: str) -> bytes:
        if name in self._modified:
            return self._modified[name]
        return self.zf.read(name)

    def read_text(self, name: str) -> tuple[str, str]:
        return _decode(self.read_raw(name))

    def write_raw(self, name: str, data: bytes) -> None:
        self._modified[name] = data

    def write_text(self, name: str, text: str, enc: str = "utf-8") -> None:
        # 保持原有的 XML 声明编码写法
        if enc.lower() != "utf-8":
            text = re.sub(r'(<\?xml[^>]*encoding=["\'])[\w-]+(["\'])',
                          lambda m: m.group(1) + enc + m.group(2), text, count=1)
        self._modified[name] = text.encode(enc, errors="xmlcharrefreplace")

    def abs_path(self, href: str) -> str:
        href = href.split("#")[0]
        return posixpath.normpath(posixpath.join(self.opf_dir, href)) if self.opf_dir else posixpath.normpath(href)

    # ------------------------------------------------------------ OPF 解析
    def _locate_opf(self) -> str:
        try:
            data = self.zf.read("META-INF/container.xml")
            root = ET.fromstring(data)
            for rf in root.iter():
                if rf.tag.endswith("rootfile"):
                    p = rf.attrib.get("full-path")
                    if p:
                        return p
        except KeyError:
            pass
        for name in self.entries:
            if name.lower().endswith(".opf"):
                return name
        raise RuntimeError("未找到 OPF 文件，可能不是有效 EPUB")

    def _parse_opf(self) -> None:
        root = ET.fromstring(self.opf_text.encode("utf-8"))
        self.manifest: dict[str, dict] = {}
        self.spine: list[str] = []
        self.title = ""

        for item in root.iter():
            if item.tag == f"{{{NS['opf']}}}item" or item.tag.endswith("}item"):
                attrs = {k.split("}")[-1]: v for k, v in item.attrib.items()}
                if "id" in attrs and "href" in attrs:
                    self.manifest[attrs["id"]] = attrs
        for item in root.iter():
            if item.tag.endswith("}itemref"):
                idref = item.attrib.get("idref")
                if idref:
                    self.spine.append(idref)
        for item in root.iter():
            if item.tag.endswith("}title"):
                if item.text and not self.title:
                    self.title = item.text.strip()
        for item in root.iter():
            if item.tag.endswith("}meta"):
                if item.attrib.get("name") == "cover":
                    self._cover_id = item.attrib.get("content")
                elif item.attrib.get("property") == "cover-image":
                    self._cover_id = item.attrib.get("content")
        self._cover_id = getattr(self, "_cover_id", None)

    # ------------------------------------------------------------ 内容清单
    def items_by_type(self, types: tuple[str, ...]) -> list[tuple[str, str]]:
        out = []
        for attrs in self.manifest.values():
            mt = (attrs.get("media-type") or "").split(";")[0].strip()
            if mt in types:
                out.append((self.abs_path(attrs["href"]), attrs.get("id", "")))
        return out

    def xhtml_items(self) -> list[str]:
        """按 spine 顺序返回正文 XHTML 路径（不在 spine 的排到最后）。"""
        ordered = []
        for idref in self.spine:
            if idref in self.manifest:
                ordered.append(self.abs_path(self.manifest[idref]["href"]))
        rest = [p for p, _ in self.items_by_type(XHTML_TYPES) if p not in ordered]
        return [p for p in ordered if p in self.entries] + [p for p in rest if p in self.entries]

    def css_items(self) -> list[str]:
        return [p for p, _ in self.items_by_type(("text/css",)) if p in self.entries]

    def image_items(self) -> list[tuple[str, int]]:
        out = []
        for p, _ in self.items_by_type(IMAGE_TYPES):
            if p in self.entries:
                try:
                    out.append((p, len(self.read_raw(p))))
                except KeyError:
                    continue
        return sorted(out, key=lambda t: -t[1])

    def cover_item(self) -> str | None:
        if self._cover_id and self._cover_id in self.manifest:
            return self.abs_path(self.manifest[self._cover_id]["href"])
        for attrs in self.manifest.values():
            props = (attrs.get("properties") or "").split()
            if "cover-image" in props:
                return self.abs_path(attrs["href"])
        imgs = self.image_items()
        return imgs[0][0] if imgs else None

    # ------------------------------------------------------------ 保存
    def save(self, out_path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with zipfile.ZipFile(out_path, "w") as zout:
            # 1) mimetype 必须第一个且 STORED
            zi = zipfile.ZipInfo("mimetype")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, MIMETYPE, compress_type=zipfile.ZIP_STORED)
            # 2) 其余条目保持原有顺序与压缩方式
            for info in self.zf.infolist():
                name = info.filename
                if name == "mimetype" or name in self._deleted:
                    continue
                data = self._modified.get(name)
                if data is None:
                    data = self.zf.read(name)
                ninfo = zipfile.ZipInfo(name, date_time=info.date_time)
                ninfo.compress_type = info.compress_type
                ninfo.external_attr = info.external_attr
                ninfo.internal_attr = info.internal_attr
                ninfo.create_system = info.create_system
                zout.writestr(ninfo, data)
            # 3) 新增条目
            for name in self._modified:
                if name in self.entries or name == "mimetype":
                    continue
                zout.writestr(name, self._modified[name], compress_type=zipfile.ZIP_DEFLATED)

    def close(self) -> None:
        self.zf.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------- 工具函数

def _make_figure(seed: int, w: int = 480, h: int = 360) -> bytes:
    """生成一张带纹理的插图（够大、有细节，适合做 DCT 水印载体）。"""
    import random
    from PIL import Image, ImageDraw
    rng = random.Random(seed)
    base = (rng.randint(180, 245), rng.randint(180, 240), rng.randint(170, 235))
    img = Image.new("RGB", (w, h), base)
    d = ImageDraw.Draw(img)
    for k in range(0, w, 24):
        d.line([(k, 0), (k, h)], fill=(base[0] - rng.randint(5, 40),
                                       base[1] - rng.randint(5, 40),
                                       base[2] - rng.randint(5, 40)))
    for _ in range(rng.randint(6, 14)):
        x0, y0 = rng.randint(0, w - 60), rng.randint(0, h - 60)
        d.ellipse([x0, y0, x0 + rng.randint(30, 90), y0 + rng.randint(30, 90)],
                  outline=(rng.randint(40, 120), rng.randint(40, 120), rng.randint(40, 140)),
                  width=rng.randint(2, 5))
    d.rectangle([8, 8, w - 9, h - 9], outline=(90, 80, 70), width=3)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88)
    return buf.getvalue()


def make_sample_epub(out_path: str, chapters: int = 3, paragraphs: int = 40,
                     figures: int = 6) -> str:
    """生成一个用于自测的中文样本 EPUB（含封面 + 若干正文插图，无需外部素材）。"""
    import random
    random.seed(20261008)
    words = "山水風雲日月星辰草木花鳥江河湖海春夏秋冬東西南北天地玄黃宇宙洪荒" \
            "讀書明理修身齊家治國平天下文章千古事得失寸心知學而不思則罔思而不學則殆"
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)

    css = """@charset "utf-8";
body { margin: 1em; line-height: 1.75; font-family: serif; text-align: justify; }
h1 { font-size: 1.6em; text-align: center; margin: 1.2em 0; font-weight: bold; }
p { text-indent: 2em; margin: 0.4em 0; font-size: 1em; }
.cover { text-align: center; page-break-after: always; }
.bold { font-weight: bold; color: #333333; }
.italic { font-style: italic; letter-spacing: 0.05em; }
img.coverimg { max-width: 100%; height: auto; display: block; margin: 0 auto; }
blockquote { margin: 1em 2em; padding: 0.5em; border-left: 2px solid #999999; }
"""

    def para(i: int, fig: str = "") -> str:
        s = "".join(random.choice(words) for _ in range(random.randint(60, 140)))
        punct = "，".join([s[k:k + 12] for k in range(0, len(s), 12)])
        cls = random.choice(["", "", ' class="bold"', ' class="italic"'])
        return f'<p{cls}>{punct}。</p>' + (f'<div class="fig"><img src="{fig}" alt="插图"/></div>' if fig else "")

    chap_files = []
    for c in range(chapters):
        imgs = [f"../images/fig{(c * figures // max(1, chapters)) + i}.jpg"
                for i in range(max(1, figures // max(1, chapters)))]
        step = max(1, paragraphs // (len(imgs) + 1))
        body_lines = []
        for i in range(paragraphs):
            fig = imgs[len(body_lines) // step] if (len(body_lines) // step) < len(imgs) and i % step == 0 else ""
            body_lines.append(para(i, fig))
        body = "\n".join(body_lines)
        xhtml = f"""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="zh-CN">
<head><meta charset="utf-8"/><title>第{c + 1}章</title>
<link rel="stylesheet" type="text/css" href="../stylesheet/main.css"/></head>
<body>
<h1>第 {c + 1} 章</h1>
{body}
<blockquote>這是第 {c + 1} 章的引文，用於測試樣式與排版保真。</blockquote>
</body>
</html>"""
        chap_files.append(xhtml)

    cover_xhtml = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="zh-CN">
<head><meta charset="utf-8"/><title>封面</title>
<link rel="stylesheet" type="text/css" href="../stylesheet/main.css"/></head>
<body class="cover"><div class="cover"><img class="coverimg" src="../images/cover.jpg" alt="cover"/></div></body>
</html>"""

    # 生成一张封面图
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (600, 800), (245, 240, 230))
    d = ImageDraw.Draw(img)
    for i in range(0, 800, 8):
        d.line([(0, i), (600, i)], fill=(235 - (i // 40), 228, 215))
    d.rectangle([60, 120, 540, 680], outline=(90, 70, 60), width=4)
    d.text((180, 380), "SAMPLE BOOK", fill=(60, 50, 40))
    ibuf = io.BytesIO()
    img.save(ibuf, "JPEG", quality=92)
    cover_bytes = ibuf.getvalue()

    fig_items = "".join(
        f'<item id="fig{i}" href="images/fig{i}.jpg" media-type="image/jpeg"/>'
        for i in range(figures))

    opf = f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bookid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>水印测试样本书</dc:title>
    <dc:language>zh-CN</dc:language>
    <dc:identifier id="bookid">urn:uuid:sample-book-0001</dc:identifier>
    <meta name="cover" content="cover-image"/>
  </metadata>
  <manifest>
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
    <item id="css" href="stylesheet/main.css" media-type="text/css"/>
    <item id="cover-image" href="images/cover.jpg" media-type="image/jpeg" properties="cover-image"/>
    <item id="cover" href="text/cover.xhtml" media-type="application/xhtml+xml"/>
    {fig_items}
    {''.join(f'<item id="chap{i}" href="text/chap{i}.xhtml" media-type="application/xhtml+xml"/>' for i in range(chapters))}
  </manifest>
  <spine toc="ncx">
    <itemref idref="cover"/>
    {''.join(f'<itemref idref="chap{i}"/>' for i in range(chapters))}
  </spine>
</package>"""

    container = """<?xml version="1.0" encoding="utf-8"?>
<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0">
  <rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles>
</container>"""

    with zipfile.ZipFile(out_path, "w") as z:
        zi = zipfile.ZipInfo("mimetype")
        zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, MIMETYPE, compress_type=zipfile.ZIP_STORED)
        z.writestr("META-INF/container.xml", container, zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/content.opf", opf, zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/stylesheet/main.css", css, zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/images/cover.jpg", cover_bytes, zipfile.ZIP_DEFLATED)
        for i in range(figures):
            z.writestr(f"OEBPS/images/fig{i}.jpg", _make_figure(1000 + i),
                       zipfile.ZIP_DEFLATED)
        z.writestr("OEBPS/text/cover.xhtml", cover_xhtml, zipfile.ZIP_DEFLATED)
        for i, x in enumerate(chap_files):
            z.writestr(f"OEBPS/text/chap{i}.xhtml", x, zipfile.ZIP_DEFLATED)
    return out_path
