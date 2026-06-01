import argparse
import hashlib
import math
import os
import pickle
import re
import sys
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from lib import abstract_method_weight


DEFAULT_DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data")
)
DEFAULT_PICKLE_DIR = os.path.join(DEFAULT_DATA_DIR, "lib_pickles_cache")
DEFAULT_SKELETON_DIR = os.path.join(DEFAULT_DATA_DIR, "lib_pickles_skeleton")


class SkeletonThirdLib:
    """A ThirdLib-compatible object built from common version-level features."""

    def __init__(self):
        self.LOGGER = None
        self.lib_name = None
        self.lib_package_name = None
        self.lib_opcode_num = 0
        self.classes_dict = {}
        self.nodes_dict = {}
        self.lib_method_num = 0
        self.interface_lib = True
        self.android_jars = []
        self.condition_jump_ins = []
        self.half_condition_jump_ins = []


SkeletonThirdLib.__module__ = "skeleton_builder"
sys.modules.setdefault("skeleton_builder", sys.modules[__name__])


def _load_pickle(path: str):
    with open(path, "rb") as file:
        return pickle.load(file)


def _pattern_text(pattern) -> str:
    return getattr(pattern, "pattern", str(pattern))


def _compile_pattern(pattern_text: str):
    return re.compile(pattern_text)


def _anchored_method_pattern(method_descriptor: str):
    return re.compile("^" + method_descriptor + "$")


def _threshold_count(total: int, threshold: float) -> int:
    return max(1, int(math.ceil(total * threshold)))


def _multiset_intersection(values: Sequence[Sequence]) -> List:
    if not values:
        return []

    intersection = list(values[0])
    for current in values[1:]:
        remaining = list(current)
        next_intersection = []
        for item in intersection:
            if item in remaining:
                next_intersection.append(item)
                remaining.remove(item)
        intersection = next_intersection
        if not intersection:
            break
    return sorted(intersection)


def _hash_opcodes(opcodes: Sequence[int]) -> str:
    digest = hashlib.md5()
    digest.update(" ".join(map(str, opcodes)).encode("utf-8"))
    return digest.hexdigest()


def _hash_class(method_md5s: Iterable[str]) -> str:
    digest = hashlib.md5()
    digest.update("".join(sorted(method_md5s)).encode("utf-8"))
    return digest.hexdigest()


def _most_common(values: Sequence, default=None):
    if not values:
        return default
    return Counter(values).most_common(1)[0][0]


def _version_sort_key(path: str) -> Tuple:
    name = os.path.basename(path)
    return tuple(part.lower() for part in re.split(r"([0-9]+)", name))


def _is_version_pickle(name: str) -> bool:
    return name.endswith(".pkl") and not name.endswith("_skeleton.pkl")


def _family_from_pickle_name(name: str) -> str:
    stem = name[:-4] if name.endswith(".pkl") else name
    match = re.match(r"^(?P<family>.+?)[_-](?P<version>\d[\w.\-+]*)$", stem)
    if match:
        prefix = match.group("family")
        if "_" in prefix:
            left, _artifact = prefix.rsplit("_", 1)
            if "." in left:
                return left
        return prefix
    return stem.rsplit("_", 1)[0] if "_" in stem else stem


def index_version_pickles(cache_dir: str) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    if not os.path.isdir(cache_dir):
        return {}

    for name in sorted(os.listdir(cache_dir)):
        if not _is_version_pickle(name):
            continue
        family = _family_from_pickle_name(name)
        families[family].append(os.path.join(cache_dir, name))

    return {
        family: sorted(paths, key=_version_sort_key)
        for family, paths in sorted(families.items())
    }


def _class_kind(class_info: list) -> str:
    return "abstract" if len(class_info) == 2 else "concrete"


def _class_desc_pattern(class_info: list) -> str:
    return _pattern_text(class_info[1] if len(class_info) == 2 else class_info[7])


def _field_sigs(class_info: list) -> List[str]:
    return list(class_info[6]) if len(class_info) > 2 else []


def _second_method_pattern(method_info: list) -> Optional[str]:
    if not method_info:
        return None
    last = method_info[-1]
    if hasattr(last, "pattern"):
        return _pattern_text(last)
    return None


def _method_extra_tuple(method_infos: Sequence[list]):
    extras = [
        method_info[5]
        for method_info in method_infos
        if len(method_info) > 5 and isinstance(method_info[5], tuple)
    ]
    return _most_common(extras)


def _index_method_nodes(lib_obj) -> Dict[str, Dict[str, list]]:
    node_index = defaultdict(dict)
    for key, value in getattr(lib_obj, "nodes_dict", {}).items():
        method_name, separator, _node_num = key.rpartition("_")
        if separator:
            node_index[method_name][key] = value
    return node_index


def _build_method_nodes(
    method_name: str,
    method_infos: Sequence[list],
    source_node_indices: Sequence[Dict[str, Dict[str, list]]],
    opcodes: Sequence[int],
) -> Dict[str, list]:
    candidates = []
    for node_index, method_info in zip(source_node_indices, method_infos):
        nodes = node_index.get(method_name, {})
        candidates.append((len(method_info[1]), len(nodes), nodes))

    if not candidates:
        return {method_name + "_1": [list(opcodes), []]}

    longest = sorted(candidates, key=lambda item: (item[0], item[1]), reverse=True)[0]
    nodes = longest[2]
    if not nodes or len(nodes) == 1:
        return {method_name + "_1": [list(opcodes), []]}
    return {key: value for key, value in sorted(nodes.items())}


def _build_abstract_class(class_versions: Sequence[list], min_count: int):
    desc_patterns = []
    pattern_counter = Counter()
    for class_info in class_versions:
        desc_patterns.append(_class_desc_pattern(class_info))
        pattern_counter.update(_pattern_text(pattern) for pattern in class_info[0])

    selected_patterns = [
        pattern
        for pattern, count in sorted(pattern_counter.items())
        if count >= min_count
    ]
    return [
        [_compile_pattern(pattern) for pattern in selected_patterns],
        _compile_pattern(_most_common(desc_patterns, "^$")),
    ]


def _build_concrete_class(
    class_name: str,
    class_versions: Sequence[Tuple[object, list]],
    node_indices: Dict[object, Dict[str, Dict[str, list]]],
    min_count: int,
):
    method_counter = Counter()
    for _lib_obj, class_info in class_versions:
        method_counter.update(class_info[4].keys())

    selected_methods = [
        method_name
        for method_name, count in sorted(method_counter.items())
        if count >= min_count
    ]
    if not selected_methods:
        return None, {}

    methods_dict = {}
    class_nodes = {}
    method_md5s = []
    class_opcode_num = 0

    for method_name in selected_methods:
        method_infos = []
        source_node_indices = []
        for lib_obj, class_info in class_versions:
            method_info = class_info[4].get(method_name)
            if method_info is not None:
                method_infos.append(method_info)
                source_node_indices.append(node_indices[lib_obj])

        opcodes = _multiset_intersection([method_info[1] for method_info in method_infos])
        method_strings = _multiset_intersection([method_info[2] for method_info in method_infos])
        if not opcodes:
            continue

        method_md5 = _hash_opcodes(opcodes)
        method_descriptor = _most_common([method_info[4] for method_info in method_infos], "")
        method_info_list = [
            method_md5,
            opcodes,
            method_strings,
            len(opcodes),
            method_descriptor,
        ]

        extra = _method_extra_tuple(method_infos)
        if extra is not None:
            method_info_list.append(extra)

        second_patterns = [
            pattern
            for pattern in (_second_method_pattern(method_info) for method_info in method_infos)
            if pattern
        ]
        if second_patterns:
            second_pattern = _most_common(second_patterns)
            method_info_list.append(_compile_pattern(second_pattern))

        methods_dict[method_name] = method_info_list
        method_md5s.append(method_md5)
        class_opcode_num += len(opcodes)
        class_nodes.update(_build_method_nodes(method_name, method_infos, source_node_indices, opcodes))

    if not methods_dict:
        return None, {}

    desc_patterns = [_class_desc_pattern(class_info) for _lib_obj, class_info in class_versions]
    class_method_sigs = []
    for method_name in selected_methods:
        method_info = methods_dict.get(method_name)
        if method_info is None:
            continue
        method_descriptor = method_info[4]
        class_method_sigs.append(_anchored_method_pattern(method_descriptor))
        second_pattern = _second_method_pattern(method_info)
        if second_pattern:
            class_method_sigs.append(_compile_pattern("^" + second_pattern + "$"))

    field_counter = Counter()
    for _lib_obj, class_info in class_versions:
        field_counter.update(set(_field_sigs(class_info)))
    field_sigs = [
        field_sig
        for field_sig, count in sorted(field_counter.items())
        if count >= min_count
    ]

    class_info = [
        _hash_class(method_md5s),
        len(methods_dict),
        class_opcode_num,
        {},
        methods_dict,
        class_method_sigs,
        field_sigs,
        _compile_pattern(_most_common(desc_patterns, "^$")),
    ]
    return class_info, class_nodes


def build_skeleton_for_family(
    family: str,
    pickle_paths: Sequence[str],
    threshold: float = 0.8,
) -> SkeletonThirdLib:
    min_count = _threshold_count(len(pickle_paths), threshold)
    return build_skeleton_from_pickles(
        family,
        pickle_paths,
        min_count,
        lib_name=family + "_skeleton",
    )


def build_skeleton_from_pickles(
    family: str,
    pickle_paths: Sequence[str],
    min_count: int,
    lib_name: Optional[str] = None,
) -> SkeletonThirdLib:
    version_paths = sorted(pickle_paths, key=_version_sort_key)
    version_objects = [_load_pickle(path) for path in version_paths]
    node_indices = {lib_obj: _index_method_nodes(lib_obj) for lib_obj in version_objects}

    skeleton = SkeletonThirdLib()
    skeleton.lib_name = lib_name or family + "_skeleton"
    skeleton.lib_package_name = family

    class_counter = Counter()
    for lib_obj in version_objects:
        class_counter.update(getattr(lib_obj, "classes_dict", {}).keys())

    selected_classes = [
        class_name
        for class_name, count in sorted(class_counter.items())
        if count >= min_count
    ]

    for class_name in selected_classes:
        class_versions = []
        for lib_obj in version_objects:
            class_info = getattr(lib_obj, "classes_dict", {}).get(class_name)
            if class_info is not None:
                class_versions.append((lib_obj, class_info))

        kind = _most_common([_class_kind(class_info) for _lib_obj, class_info in class_versions])
        if kind == "abstract":
            abstract_infos = [
                class_info
                for _lib_obj, class_info in class_versions
                if _class_kind(class_info) == "abstract"
            ]
            class_info = _build_abstract_class(abstract_infos, min_count)
            if class_info is None:
                continue
            skeleton.classes_dict[class_name] = class_info
            skeleton.lib_opcode_num += len(class_info[0]) * abstract_method_weight
            continue

        concrete_versions = [
            (lib_obj, class_info)
            for lib_obj, class_info in class_versions
            if _class_kind(class_info) == "concrete"
        ]
        class_info, class_nodes = _build_concrete_class(class_name, concrete_versions, node_indices, min_count)
        if class_info is None:
            continue
        skeleton.interface_lib = False
        skeleton.classes_dict[class_name] = class_info
        skeleton.nodes_dict.update(class_nodes)
        skeleton.lib_method_num += class_info[1]
        skeleton.lib_opcode_num += class_info[2]

    return skeleton


def build_skeleton_pickles(
    pickle_dir: str,
    output_dir: str,
    families: Optional[Iterable[str]] = None,
    threshold: float = 0.8,
    overwrite: bool = False,
) -> Dict[str, str]:
    indexed = index_version_pickles(pickle_dir)
    requested = set(families or indexed.keys())
    os.makedirs(output_dir, exist_ok=True)

    written = {}
    for family in sorted(requested):
        pickle_paths = indexed.get(family, [])
        if not pickle_paths:
            raise FileNotFoundError(f"No version pickles found for family: {family}")
        output_path = os.path.join(output_dir, family + "_skeleton.pkl")
        if os.path.exists(output_path) and not overwrite:
            raise FileExistsError(f"Skeleton pickle already exists: {output_path}")

        skeleton = build_skeleton_for_family(
            family,
            pickle_paths,
            threshold=threshold,
        )
        with open(output_path, "wb") as file:
            pickle.dump(skeleton, file)
        written[family] = output_path

    return written


def parse_args(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(description="Build ThirdLib skeleton pickles from version pickles")
    parser.add_argument(
        "-p",
        "--pickle-dir",
        default=DEFAULT_PICKLE_DIR,
        help="Directory containing version ThirdLib pickles",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_SKELETON_DIR,
        help="Directory to write skeleton pickles",
    )
    parser.add_argument("-f", "--family", action="append", default=None, help="Library family to build")
    parser.add_argument("-t", "--threshold", type=float, default=0.8, help="Version occurrence threshold")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing output skeleton pickles")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    written = build_skeleton_pickles(
        args.pickle_dir,
        args.output_dir,
        families=args.family,
        threshold=args.threshold,
        overwrite=args.overwrite,
    )
    for family, path in written.items():
        print(f"{family}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
