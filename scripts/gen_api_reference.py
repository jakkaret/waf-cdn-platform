#!/usr/bin/env python3
"""Regenerate docs/reference/api-reference.md from dashboard/backend/api/*.py.

Reads the source with ast (no app import, so no env or database needed):
routers declared as `X = APIRouter(prefix=...)`, handlers decorated with
`@X.get/post/put/patch/delete(path)` or `@X.api_route(path, methods=[...])`,
the auth dependencies in their parameters or `dependencies=[...]`, and which
routers main.py includes. dashboard/backend/tests/test_api_reference_doc.py
fails when the committed file differs from this output.

    python3 scripts/gen_api_reference.py          # rewrite the doc
    python3 scripts/gen_api_reference.py --check  # exit 1 if it is stale
"""
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "dashboard" / "backend" / "api"
MAIN = ROOT / "dashboard" / "backend" / "main.py"
DOC = ROOT / "docs" / "reference" / "api-reference.md"

METHODS = ("get", "post", "put", "patch", "delete")
AUTH = {
    "require_admin": "admin",
    "require_viewer_or_above": "viewer+",
    "get_current_user": "login",
    "bearer_scheme": "bearer token",
    "verify_internal_deception_key": "internal key",
    "verify_origin_ownership": "origin owner",
    "verify_origin_access": "origin read",
    "verify_origin_edit_access": "origin edit",
}

HEADER = """---
title: "API Reference"
part: "Reference"
status: VERIFIED
---

# API Reference

สร้างอัตโนมัติจากซอร์สโค้ด `dashboard/backend/api/*.py` ด้วย `scripts/gen_api_reference.py` (อ่าน AST ไม่ได้ import แอปจริง) แก้ไฟล์นี้ด้วยมือไม่ได้ ให้รันสคริปต์ใหม่แทน ช่อง **Auth** มาจาก dependency ที่ประกาศใน decorator/พารามิเตอร์ของ handler: `admin` = `require_admin`, `viewer+` = `require_viewer_or_above`, `login` = `get_current_user`, `bearer token` = `bearer_scheme`, `internal key` = header ภายในจาก nginx, `origin owner/read/edit` = `verify_origin_*` (ต้อง login และมีสิทธิ์ต่อ origin นั้น), `public` = ไม่พบ dependency ด้านการยืนยันตัวตน (บาง handler อาจตรวจสิทธิ์เองในโค้ด ให้ดูไฟล์ประกอบ)

Route ที่ประกาศใน `main.py` เอง (`/api/health`, `/api/system/*`, ไฟล์ static) อยู่นอกขอบเขตของไฟล์นี้
"""


def _str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _depends(node):
    """Names passed to Depends(...) anywhere inside node, in source order."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "Depends" and n.args:
            name = getattr(n.args[0], "id", None) or getattr(n.args[0], "attr", None)
            if name:
                out.append(name)
    return out


def _docline(fn):
    doc = ast.get_docstring(fn) or ""
    return doc.strip().splitlines()[0].replace("|", "\\|") if doc.strip() else ""


def routes(path: pathlib.Path):
    """[(router_name, [methods], full_path, handler, auth, docline, in_schema)] for one api module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    prefixes = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "id", None) == "APIRouter"):
            prefix = next((_str(k.value) for k in node.value.keywords if k.arg == "prefix"), "") or ""
            for t in node.targets:
                if isinstance(t, ast.Name):
                    prefixes[t.id] = prefix
    out = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in fn.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name) and dec.func.value.id in prefixes):
                continue
            kind = dec.func.attr
            if kind in METHODS:
                methods = [kind.upper()]
            elif kind == "api_route":
                methods = next(([_str(e).upper() for e in k.value.elts] for k in dec.keywords if k.arg == "methods"), ["GET"])
            else:
                continue
            sub = _str(dec.args[0]) if dec.args else next((_str(k.value) for k in dec.keywords if k.arg == "path"), "")
            deps = _depends(dec) + _depends(fn.args)
            auth = ", ".join(dict.fromkeys(AUTH[d] for d in deps if d in AUTH)) or "public"
            in_schema = not any(k.arg == "include_in_schema" and isinstance(k.value, ast.Constant)
                                and k.value.value is False for k in dec.keywords)
            out.append((dec.func.value.id, methods, prefixes[dec.func.value.id] + (sub or ""), fn.name, auth,
                        _docline(fn), in_schema))
    return out


def registered():
    """{(module, router_name)} that main.py passes to app.include_router."""
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    alias = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "api":
            for a in node.names:
                alias[a.asname or a.name] = a.name
    out = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "include_router" and node.args
                and isinstance(node.args[0], ast.Attribute) and isinstance(node.args[0].value, ast.Name)):
            mod = alias.get(node.args[0].value.id)
            if mod:
                out.add((mod, node.args[0].attr))
    return out


def served(schema_only: bool = False):
    """{(METHOD, path)} for every route main.py serves from api/*.py."""
    reg = registered()
    return {(m, p) for f in sorted(API.glob("*.py")) for r, ms, p, *_rest, in_schema in routes(f)
            if (f.stem, r) in reg and (in_schema or not schema_only) for m in ms}


def render() -> str:
    reg = registered()
    sections, total, files = [], 0, 0
    for f in sorted(API.glob("*.py")):
        rows = routes(f)
        if not rows:
            continue
        files += 1
        total += len(rows)
        on = {r for r, *_ in rows if (f.stem, r) in reg}
        status = ("ลงทะเบียนใน main.py" if len(on) == len({r for r, *_ in rows})
                  else "ลงทะเบียนบางส่วน" if on else "ไม่ได้ลงทะเบียนใน main.py (ไม่ถูกเรียกใช้จริง)")
        lines = [f"## `api/{f.name}`", "", f"สถานะการลงทะเบียน: {status}", "",
                 "| Method | Path | Handler | Auth | คำอธิบาย (docstring) |", "|---|---|---|---|---|"]
        for _r, ms, p, handler, auth, doc, _s in sorted(rows, key=lambda x: (x[2], x[1])):
            lines.append(f"| {','.join(ms)} | `{p}` | `{handler}` | {auth} | {doc} |")
        sections.append("\n".join(lines))
    summary = f"พบทั้งหมด **{total} endpoints** ใน **{files} ไฟล์** — router ที่ `main.py` ลงทะเบียน (`include_router`) มี {len(reg)} รายการ"
    return HEADER + "\n" + summary + "\n\n" + "\n\n".join(sections) + "\n"


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        stale = DOC.read_text(encoding="utf-8") != text
        print("stale: run python3 scripts/gen_api_reference.py" if stale else "up to date")
        sys.exit(1 if stale else 0)
    DOC.write_text(text, encoding="utf-8")
    print(f"wrote {DOC.relative_to(ROOT)}")
