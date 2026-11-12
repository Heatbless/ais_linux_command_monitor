"""Fetch pinned text datasets and a bounded AIT ZIP inventory; execute no data."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import urllib.request
import zipfile
from collections import OrderedDict
from pathlib import Path

COWRIE_BASE = (
    "https://raw.githubusercontent.com/zyw-286/shell-attack-evolution-dataset/main/"
)
COWRIE_FILES = {
    "2021_2022.jsonl": (8602471, "28e5b2d41a2e22e40bab9d086a6044a1c473c8ab"),
    "2024.jsonl": (7200297, "c2fbea787f95b71f93fa2a06d9264a59f87e6409"),
}
AIT_URL = (
    "https://zenodo.org/records/19483937/files/russellmitchell_no-pcaps.zip?download=1"
)
AIT_V1_URL = "https://zenodo.org/records/4264796/files/AIT-LDS-v1_1.zip?download=1"


def get(url, maximum):
    request = urllib.request.Request(
        url, headers={"User-Agent": "AIS-offline-research/0.1"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ValueError("Download exceeds declared text-data limit")
    return body


class RemoteZip(io.RawIOBase):
    """Seekable HTTP range reader with an overall download budget and LRU cache.

    Refuse full-body responses: a server ignoring Range must never cause a
    surprise half-gigabyte download. Fetch at most one MiB per cache block.
    """

    def __init__(self, url, budget=64 * 1024 * 1024):
        self.url, self.budget, self.downloaded, self.position = url, budget, 0, 0
        self.cache = OrderedDict()
        self.block_size = 1024 * 1024
        request = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": "AIS-offline-research/0.1"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            self.size = int(response.headers["Content-Length"])
        if self.size <= 0:
            raise ValueError("Remote ZIP length unavailable")

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        if whence not in (0, 1, 2):
            raise ValueError("Unsupported seek mode")
        position = (
            offset
            if whence == 0
            else (self.position if whence == 1 else self.size) + offset
        )
        if position < 0:
            raise ValueError("Negative seek")
        self.position = position
        return position

    def block(self, index):
        if index in self.cache:
            self.cache.move_to_end(index)
            return self.cache[index]
        start = index * self.block_size
        end = min(start + self.block_size, self.size) - 1
        expected = end - start + 1
        if self.downloaded + expected > self.budget:
            raise ValueError("AIT transfer budget exhausted")
        request = urllib.request.Request(
            self.url,
            headers={
                "Range": f"bytes={start}-{end}",
                "User-Agent": "AIS-offline-research/0.1",
                "Accept-Encoding": "identity",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            if (
                response.status != 206
                or response.headers.get("Content-Range")
                != f"bytes {start}-{end}/{self.size}"
            ):
                raise ValueError(
                    "Server does not honor exact byte ranges; full archive was not downloaded"
                )
            data = response.read(expected + 1)
        if len(data) != expected:
            raise ValueError("Incorrect HTTP range size")
        self.downloaded += len(data)
        self.cache[index] = data
        while len(self.cache) > 8:
            self.cache.popitem(last=False)
        return data

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.position
        size = min(size, max(0, self.size - self.position))
        if size > self.budget:
            raise ValueError("Requested read exceeds transfer budget")
        result = []
        while size:
            block = self.block(self.position // self.block_size)
            offset = self.position % self.block_size
            length = min(size, len(block) - offset)
            result.append(block[offset : offset + length])
            self.position += length
            size -= length
        return b"".join(result)


class StoredMember(io.RawIOBase):
    """Seek inside an uncompressed ZIP member without downloading it whole."""

    def __init__(self, parent, info):
        if info.compress_type != zipfile.ZIP_STORED:
            raise ValueError("Nested random access requires a stored outer member")
        parent.seek(info.header_offset)
        header = parent.read(30)
        if header[:4] != b"PK\x03\x04":
            raise ValueError("Invalid local ZIP header")
        name_length, extra_length = struct.unpack_from("<HH", header, 26)
        self.parent = parent
        self.start = info.header_offset + 30 + name_length + extra_length
        self.size = info.file_size
        self.position = 0

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        if whence not in (0, 1, 2):
            raise ValueError("Invalid seek mode")
        target = (
            offset
            if whence == 0
            else (self.position if whence == 1 else self.size) + offset
        )
        if target < 0:
            raise ValueError("Negative seek")
        self.position = target
        return target

    def read(self, size=-1):
        size = (
            max(0, self.size - self.position)
            if size < 0
            else min(size, max(0, self.size - self.position))
        )
        self.parent.seek(self.start + self.position)
        result = self.parent.read(size)
        self.position += len(result)
        return result


def fetch_cowrie(root):
    directory = root / "cowrie"
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "source": "https://github.com/zyw-286/shell-attack-evolution-dataset",
        "license": "CC BY 4.0 for dataset; authors Wang et al., SRDS 2025",
        "purpose": "external evaluation only; not normal training",
        "files": [],
    }
    for name, (size, expected) in COWRIE_FILES.items():
        target = directory / name
        url = COWRIE_BASE + "dataset/sessions/" + name
        body = target.read_bytes() if target.exists() else get(url, size)
        blob_hash = hashlib.sha1(f"blob {len(body)}\0".encode() + body).hexdigest()
        if len(body) != size or blob_hash != expected:
            raise ValueError("Cowrie size or pinned Git blob checksum mismatch")
        if not target.exists():
            target.write_bytes(body)
        manifest["files"].append(
            {
                "file": name,
                "url": url,
                "bytes": size,
                "git_blob_sha1": expected,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
        print(f"Cowrie {name}: {size} bytes verified", flush=True)
    (directory / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def ait_inventory(root, extract=False):
    directory = root / "ait"
    directory.mkdir(parents=True, exist_ok=True)
    remote = RemoteZip(AIT_URL)
    with zipfile.ZipFile(remote) as archive:
        members = [
            {
                "name": i.filename,
                "bytes": i.file_size,
                "compressed_bytes": i.compress_size,
                "crc32": i.CRC,
            }
            for i in archive.infolist()
            if ("/audit/" in i.filename or i.filename.endswith("dataset.yml"))
            and not i.is_dir()
        ]
        extracted = []
        if extract:
            for member in members:
                name = member["name"]
                if not name.endswith("/logs/audit/audit.log") or not name.startswith(
                    ("gather/", "labels/")
                ):
                    continue
                path = Path(name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or member["bytes"] > 10 * 1024 * 1024
                ):
                    raise ValueError("Unsafe or oversized audit member")
                data = archive.read(name)
                target = directory / "members" / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                extracted.append(
                    {
                        "name": name,
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
    manifest = {
        "source": "https://zenodo.org/records/19483937",
        "url": AIT_URL,
        "archive_bytes": remote.size,
        "inventory_transfer_bytes": remote.downloaded,
        "purpose": "external per-host benchmark; never merge hosts into personal profiles",
        "members": members,
    }
    manifest["extracted_members"] = extracted
    (directory / "inventory.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        f"AIT inventory: {len(members)} audit/metadata members; transferred {remote.downloaded} bytes",
        flush=True,
    )
    return manifest


def ait_v1_inventory(root):
    directory = root / "ait-v1"
    directory.mkdir(parents=True, exist_ok=True)
    remote = RemoteZip(AIT_V1_URL)
    with zipfile.ZipFile(remote) as archive:
        members = [
            {
                "name": i.filename,
                "bytes": i.file_size,
                "compressed_bytes": i.compress_size,
                "compression": i.compress_type,
                "offset": i.header_offset,
                "crc32": i.CRC,
            }
            for i in archive.infolist()
            if not i.is_dir() and "audit" in i.filename.lower()
        ]
    manifest = {
        "source": "https://zenodo.org/records/4264796",
        "url": AIT_V1_URL,
        "archive_bytes": remote.size,
        "inventory_transfer_bytes": remote.downloaded,
        "members": members,
    }
    (directory / "inventory.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2), flush=True)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("private-data/external"))
    parser.add_argument(
        "--source", choices=["cowrie", "ait", "ait-v1", "all"], default="all"
    )
    parser.add_argument("--ait-members", action="store_true")
    args = parser.parse_args()
    if args.source in {"cowrie", "all"}:
        fetch_cowrie(args.output)
    if args.source in {"ait", "all"}:
        ait_inventory(args.output, extract=args.ait_members)
    if args.source == "ait-v1":
        ait_v1_inventory(args.output)
