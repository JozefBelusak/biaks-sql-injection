"""Vytvorí odovzdávací ZIP a jeho identickú kópiu s príponou .pdf."""

import shutil
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parent


def main():
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    archive = output / "zadanie2.zip"
    files = [ROOT / name for name in (
        "app.py", "schema.sql", "readme.md", "dokumentacia.md",
        "package_submission.py", ".gitignore",
    )]
    for folder in ("static", "tests", "docs"):
        files.extend(path for path in sorted((ROOT / folder).rglob("*"))
                     if path.is_file() and "__pycache__" not in path.parts)
    with ZipFile(archive, "w", ZIP_DEFLATED) as package:
        for path in files:
            package.write(path, Path("zadanie2") / path.relative_to(ROOT))
    renamed = archive.with_suffix(".zip.pdf")
    shutil.copyfile(archive, renamed)
    print(f"ZIP: {archive}")
    print(f"Na odovzdanie: {renamed}")
    print("Súbor .zip.pdf je ZIP archív s pridanou príponou .pdf podľa zadania.")


if __name__ == "__main__":
    main()
