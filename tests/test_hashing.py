from pathlib import Path

from doc_static_scanner.hashing import calculate_hashes


def test_calculate_hashes(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    hashes = calculate_hashes(sample)
    assert hashes["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert hashes["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hashes["sha512"].startswith("ddaf35a193617abacc417349ae204131")

