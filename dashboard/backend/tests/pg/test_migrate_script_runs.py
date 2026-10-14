"""db/migrate.py runs as a plain script (python db/migrate.py): a module in
db/ must never shadow the standard library (db/types.py once did)."""
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]


def test_migrate_script_starts():
    out = subprocess.run([sys.executable, str(BACKEND / "db" / "migrate.py"), "--help"],
                         capture_output=True, text=True, cwd=BACKEND, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "usage" in out.stdout.lower()


def test_no_db_module_shadows_the_standard_library():
    names = {p.stem for p in (BACKEND / "db").glob("*.py")}
    assert not names & set(sys.stdlib_module_names)
