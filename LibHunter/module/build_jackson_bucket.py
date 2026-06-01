import argparse
import math
import os
import pickle
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence

from skeleton_builder import (
    DEFAULT_DATA_DIR,
    DEFAULT_PICKLE_DIR,
    build_skeleton_from_pickles,
)


DEFAULT_TPL_DEX_DIR = os.path.join(DEFAULT_DATA_DIR, "tpl_dex")
DEFAULT_BUCKET_DIR = os.path.join(DEFAULT_DATA_DIR, "lib_pickles_buckets")
JACKSON_DATABIND = "com.fasterxml.jackson.core.jackson-databind"


def _natural_key(value: str):
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value)]


def _artifact_name(family: str) -> str:
    return family.rsplit(".", 1)[-1]


def _version_from_artifact_file(filename: str, family: str, suffix: str) -> Optional[str]:
    if not filename.endswith(suffix):
        return None
    stem = filename[:-len(suffix)]
    artifact = _artifact_name(family)
    prefix = artifact + "-"
    if not stem.startswith(prefix):
        return None
    return stem[len(prefix):].strip()


def _version_from_pickle_file(filename: str, family: str) -> Optional[str]:
    if not filename.endswith(".pkl") or filename.endswith("_skeleton.pkl"):
        return None
    stem = filename[:-4]
    prefix = family + "_"
    if not stem.startswith(prefix):
        return None
    return _version_from_artifact_file(stem[len(prefix):] + ".pkl", family, ".pkl")


def _major_minor_bucket(version: str) -> str:
    match = re.match(r"^(\d+)\.(\d+)(?:\.|$)", version)
    if not match:
        raise ValueError(f"Cannot derive major.minor bucket from version: {version}")
    return f"{match.group(1)}.{match.group(2)}.x"


def _support_count(version_count: int, threshold: float) -> int:
    return max(1, int(math.floor(version_count * threshold)))


def _versions_from_tpl_dex(tpl_dex_dir: str, family: str) -> List[str]:
    family_dir = os.path.join(tpl_dex_dir, family)
    if not os.path.isdir(family_dir):
        raise FileNotFoundError(f"TPL dex family directory not found: {family_dir}")

    versions = []
    for name in sorted(os.listdir(family_dir), key=_natural_key):
        version = _version_from_artifact_file(name, family, ".dex")
        if version:
            versions.append(version)
    return versions


def _version_pickle_index(pickle_dir: str, family: str) -> Dict[str, str]:
    index = {}
    if not os.path.isdir(pickle_dir):
        raise FileNotFoundError(f"Version pickle directory not found: {pickle_dir}")

    for name in sorted(os.listdir(pickle_dir), key=_natural_key):
        version = _version_from_pickle_file(name, family)
        if version:
            index[version] = os.path.join(pickle_dir, name)
    return index


def build_jackson_bucket_pickles(
    pickle_dir: str,
    tpl_dex_dir: str,
    output_dir: str,
    threshold: float = 0.8,
    buckets: Optional[Iterable[str]] = None,
    overwrite: bool = False,
) -> Dict[str, str]:
    family = JACKSON_DATABIND
    versions = _versions_from_tpl_dex(tpl_dex_dir, family)
    pickle_index = _version_pickle_index(pickle_dir, family)
    requested_buckets = set(buckets or [])

    grouped = defaultdict(list)
    for version in versions:
        if version not in pickle_index:
            raise FileNotFoundError(f"Missing version pickle for {family} {version}")
        bucket = _major_minor_bucket(version)
        if requested_buckets and bucket not in requested_buckets:
            continue
        grouped[bucket].append(version)

    family_output_dir = os.path.join(output_dir, family)
    os.makedirs(family_output_dir, exist_ok=True)

    written = {}
    for bucket in sorted(grouped, key=_natural_key):
        bucket_versions = sorted(grouped[bucket], key=_natural_key)
        support = _support_count(len(bucket_versions), threshold)
        pickle_paths = [pickle_index[version] for version in bucket_versions]
        lib_name = f"{family}_{bucket}_bucket"
        bucket_obj = build_skeleton_from_pickles(family, pickle_paths, support, lib_name=lib_name)
        bucket_obj.bucket_name = bucket
        bucket_obj.bucket_versions = bucket_versions
        bucket_obj.bucket_support = support

        output_path = os.path.join(family_output_dir, bucket + ".pkl")
        if os.path.exists(output_path) and not overwrite:
            raise FileExistsError(f"Bucket pickle already exists: {output_path}")
        with open(output_path, "wb") as file:
            pickle.dump(bucket_obj, file)
        written[bucket] = output_path

    return written


def parse_args(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(description="Build jackson-databind major.minor bucket skeleton pickles")
    parser.add_argument("-p", "--pickle-dir", default=DEFAULT_PICKLE_DIR, help="Version pickle directory")
    parser.add_argument("--tpl-dex-dir", default=DEFAULT_TPL_DEX_DIR, help="TPL dex directory")
    parser.add_argument("-o", "--output-dir", default=DEFAULT_BUCKET_DIR, help="Bucket pickle output directory")
    parser.add_argument("-t", "--threshold", type=float, default=0.8, help="Bucket support threshold")
    parser.add_argument("-b", "--bucket", action="append", default=None, help="Specific bucket to build")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing bucket pickles")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    written = build_jackson_bucket_pickles(
        pickle_dir=args.pickle_dir,
        tpl_dex_dir=args.tpl_dex_dir,
        output_dir=args.output_dir,
        threshold=args.threshold,
        buckets=args.bucket,
        overwrite=args.overwrite,
    )
    for bucket, path in written.items():
        print(f"{JACKSON_DATABIND} {bucket}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
