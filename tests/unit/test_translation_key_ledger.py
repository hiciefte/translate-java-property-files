import json
import tempfile
from pathlib import Path

from src.translate_localization_files import (
    build_file_key_ledger,
    compute_ledger_hash,
    load_translation_key_ledger,
    save_translation_key_ledger
)


def test_load_translation_key_ledger_missing_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        ledger_path = Path(temp_dir) / "missing-ledger.json"
        loaded = load_translation_key_ledger(str(ledger_path))
        assert loaded == {}


def test_translation_key_ledger_roundtrip():
    with tempfile.TemporaryDirectory() as temp_dir:
        ledger_path = Path(temp_dir) / "ledger.json"
        key_ledger = {
            "mobile_de.properties": {
                "key.one": {
                    "source_hash": compute_ledger_hash("Source one"),
                    "target_hash": compute_ledger_hash("Ziel eins")
                }
            }
        }

        save_translation_key_ledger(str(ledger_path), key_ledger)
        loaded = load_translation_key_ledger(str(ledger_path))

        assert loaded == key_ledger


def test_translation_key_ledger_timestamp_uses_utc_z_suffix():
    with tempfile.TemporaryDirectory() as temp_dir:
        ledger_path = Path(temp_dir) / "ledger.json"
        key_ledger = {
            "mobile_de.properties": {
                "key.one": {
                    "source_hash": compute_ledger_hash("Source one"),
                    "target_hash": compute_ledger_hash("Ziel eins")
                }
            }
        }

        save_translation_key_ledger(str(ledger_path), key_ledger)
        with open(ledger_path, "r", encoding="utf-8") as ledger_file:
            payload = json.load(ledger_file)

        assert payload["updated_at"].endswith("Z")


def test_build_file_key_ledger_replaces_removed_keys():
    source_translations = {
        "key.keep": "Source Keep",
        "key.new": "Source New"
    }
    final_translations = {
        "key.keep": "Ziel Keep",
        "key.new": "Ziel New"
    }

    built = build_file_key_ledger(source_translations, final_translations)

    assert set(built.keys()) == {"key.keep", "key.new"}
    assert built["key.keep"]["source_hash"] == compute_ledger_hash("Source Keep")
    assert built["key.keep"]["target_hash"] == compute_ledger_hash("Ziel Keep")
