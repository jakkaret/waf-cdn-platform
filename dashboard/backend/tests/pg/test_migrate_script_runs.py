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


def test_hidden_files_are_not_migrations(tmp_path):
    from db import migrate
    (tmp_path / "0001_init.sql").write_text("select 1;")
    (tmp_path / "._0001_init.sql").write_bytes(b"\x00\x05\x16\x07 macOS metadata")
    (tmp_path / ".0002_draft.sql").write_text("select 2;")
    assert [p.name for p in migrate.migration_files(tmp_path)] == ["0001_init.sql"]
