"""H03: the ML host installs an explicit commit/tag and checks model hashes."""
import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
INSTALL = (REPO / "deploy/azure-ml/install.sh").read_text()
MODELS = REPO / "ml/models"


def test_install_requires_ref_and_detaches():
    assert 'REF="${REF:-}"' in INSTALL
    assert '[ -n "$REF" ] ||' in INSTALL
    assert 'checkout -q --detach "$REF^{commit}"' in INSTALL
    assert "BRANCH" not in INSTALL and "origin/main" not in INSTALL


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
