"""H03: the ML host installs an explicit commit/tag and checks model hashes."""
import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
INSTALL = (REPO / "deploy/azure-ml/install.sh").read_text()
MODELS = REPO / "ml/models"


def test_install_requires_ref_and_detaches():
    assert 'REF="${REF:-}"' in INSTALL
    assert '[ -n "$REF" ] ||' in INSTALL
    assert 'checkout -q --detach "$COMMIT"' in INSTALL
    assert "BRANCH" not in INSTALL and "origin/main" not in INSTALL


def _ref_check(tmp_path, ref, tags=()):
    """Run install.sh's REF check against a throwaway repo with one commit
    on branch main and the given tags. Returns (exit code, output)."""
    import subprocess
    repo = tmp_path / "repo"
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", "x"], check=True)
    for t in tags:
        subprocess.run(git + ["tag", t], check=True)
    sha = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    start = INSTALL.index("# REF check start")
    end = INSTALL.index("# REF check end")
    script = "set -euo pipefail\n" + INSTALL[start:end] + 'echo "COMMIT=$COMMIT"\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "APP_DIR": str(repo),
                            "REF": ref.replace("<sha>", sha).replace("<short>", sha[:12])})
    return r.returncode, r.stdout + r.stderr, sha


def test_ref_accepts_full_sha_and_tag(tmp_path):
    code, out, sha = _ref_check(tmp_path, "<sha>")
    assert code == 0 and f"COMMIT={sha}" in out, out
    code, out, sha = _ref_check(tmp_path / "t", "v1.0.0", tags=["v1.0.0"])
    assert code == 0 and f"COMMIT={sha}" in out, out


def test_ref_refuses_branch_and_short_sha(tmp_path):
    # A branch would deploy whatever it points at; a short sha can become ambiguous.
    code, out, _ = _ref_check(tmp_path, "main")
    assert code != 0 and "full 40-character commit sha or a tag" in out, out
    code, out, _ = _ref_check(tmp_path / "s", "<short>")
    assert code != 0 and "full 40-character commit sha or a tag" in out, out


def test_install_verifies_model_hashes_and_unpickles_nothing():
    assert "sha256sum --strict -c" in INSTALL
    assert "onnx_export" not in INSTALL and "joblib" not in INSTALL


def test_sha256sums_match_committed_models():
    lines = [l for l in (MODELS / "SHA256SUMS").read_text().splitlines() if l and not l.startswith("#")]
    names = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        names.add(name)
        assert hashlib.sha256((MODELS / name).read_bytes()).hexdigest() == digest, name
    assert {"random_forest_waf.npz", "isolation_forest_waf.npz", "gen3/gen3_f_noopenappsec.onnx"} <= names
