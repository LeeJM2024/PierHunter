# LibHunter 程序入口
import argparse
import os
import sys
import zipfile

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SYSTEM_DATA_DIR = os.path.join(PROJECT_DIR, "data")
MODULE_DIR = os.path.join(os.path.dirname(__file__), "module")

os.environ.setdefault("LH_VERSION_PICKLE_DIR", os.path.join(SYSTEM_DATA_DIR, "lib_pickles_cache"))
os.environ.setdefault("LH_SKELETON_PICKLE_DIR", os.path.join(SYSTEM_DATA_DIR, "lib_pickles_skeleton"))
os.environ.setdefault("LH_BUCKET_PICKLE_DIR", os.path.join(SYSTEM_DATA_DIR, "lib_pickles_buckets"))
os.environ.setdefault("LH_APK_PICKLE_DIR", os.path.join(SYSTEM_DATA_DIR, "apk_pickles_cache"))
if MODULE_DIR not in sys.path:
    sys.path.insert(0, MODULE_DIR)

from module.lh_config import setup_logger, clear_log

from module.analyzer import search_lib_in_app, search_libs_in_app


def parse_arguments():
    parser = argparse.ArgumentParser(description="LibHunter: Android TPL detection")
    subparsers = parser.add_subparsers(help="sub-command help", dest="subparser_name")

    # ── detect_one：单库模式（多 APK 并行） ───────────────────────────────
    parser_one = subparsers.add_parser(
        "detect_one",
        help="Detection mode (Single): detect if multiple apps contain a specific TPL version",
    )
    parser_one.add_argument("-o",  metavar="FOLDER", type=str, default="outputs",
                            help="Output directory")
    parser_one.add_argument("-p",  metavar="num_processes", type=int, default=None,
                            help="Max number of processes (default=#CPU_cores)")
    parser_one.add_argument("-af", metavar="FOLDER", type=str, help="Directory of APKs")
    parser_one.add_argument("-lf", metavar="FOLDER", type=str, help="Directory of TPL JARs")
    parser_one.add_argument("-ld", metavar="FOLDER", type=str, help="Directory of TPL DEXes")

    # ── detect_all：多库模式（多库并行） ─────────────────────────────────
    parser_specific = subparsers.add_parser(
        "detect_all",
        help="Detection mode (Multiple): detect if multiple apps contain multiple TPL versions",
    )
    parser_specific.add_argument("-o",  metavar="FOLDER", type=str, default="outputs",
                                 help="Output directory")
    parser_specific.add_argument("-p",  metavar="num_processes", type=int, default=None,
                                 help="Max number of processes (default=#CPU_cores)")
    parser_specific.add_argument("-af", metavar="FOLDER", type=str, help="Directory of APKs")
    parser_specific.add_argument("-lf", metavar="FOLDER", type=str, help="Directory of TPL JARs")
    parser_specific.add_argument("-ld", metavar="FOLDER", type=str, help="Directory of TPL DEXes")

    # ── build_skeleton：从版本级 pkl 构建库级 skeleton pkl ────────────────
    parser_skeleton = subparsers.add_parser(
        "build_skeleton",
        help="Build library-level skeleton ThirdLib pickles from version pickles",
    )
    parser_skeleton.add_argument("-p", "--pickle-dir", type=str, default=None,
                                 help="Directory containing version ThirdLib pickles")
    parser_skeleton.add_argument("-o", "--output-dir", type=str, default=None,
                                 help="Directory to write skeleton pickles")
    parser_skeleton.add_argument("-f", "--family", action="append", default=None,
                                 help="Library family to build")
    parser_skeleton.add_argument("-t", "--threshold", type=float, default=0.8,
                                 help="Class and method occurrence threshold")
    parser_skeleton.add_argument("--overwrite", action="store_true",
                                 help="Overwrite existing skeleton pickles")

    # ── build_jackson_bucket：构建 jackson-databind 大版本 bucket pkl ─────
    parser_bucket = subparsers.add_parser(
        "build_jackson_bucket",
        help="Build jackson-databind major.minor bucket skeleton pickles",
    )
    parser_bucket.add_argument("-p", "--pickle-dir", type=str, default=None,
                               help="Directory containing version ThirdLib pickles")
    parser_bucket.add_argument("--tpl-dex-dir", type=str, default=None,
                               help="Directory containing TPL dex versions")
    parser_bucket.add_argument("-o", "--output-dir", type=str, default=None,
                               help="Directory to write bucket pickles")
    parser_bucket.add_argument("-t", "--threshold", type=float, default=0.8,
                               help="Bucket support threshold")
    parser_bucket.add_argument("-b", "--bucket", action="append", default=None,
                               help="Specific bucket to build")
    parser_bucket.add_argument("--overwrite", action="store_true",
                               help="Overwrite existing bucket pickles")

    # ── build_guava_bucket：构建 guava major bucket pkl ─────────────────
    parser_guava_bucket = subparsers.add_parser(
        "build_guava_bucket",
        help="Build Guava major bucket skeleton pickles",
    )
    parser_guava_bucket.add_argument("-p", "--pickle-dir", type=str, default=None,
                                     help="Directory containing version ThirdLib pickles")
    parser_guava_bucket.add_argument("--tpl-dex-dir", type=str, default=None,
                                     help="Directory containing TPL dex versions")
    parser_guava_bucket.add_argument("-o", "--output-dir", type=str, default=None,
                                     help="Directory to write bucket pickles")
    parser_guava_bucket.add_argument("-t", "--threshold", type=float, default=0.8,
                                     help="Bucket support threshold")
    parser_guava_bucket.add_argument("-b", "--bucket", action="append", default=None,
                                     help="Specific bucket to build")
    parser_guava_bucket.add_argument("--overwrite", action="store_true",
                                     help="Overwrite existing bucket pickles")

    # ── build_kotlin_bucket：构建 kotlin-stdlib major.minor bucket pkl ───
    parser_kotlin_bucket = subparsers.add_parser(
        "build_kotlin_bucket",
        help="Build kotlin-stdlib major.minor bucket skeleton pickles",
    )
    parser_kotlin_bucket.add_argument("-p", "--pickle-dir", type=str, default=None,
                                      help="Directory containing version ThirdLib pickles")
    parser_kotlin_bucket.add_argument("--tpl-dex-dir", type=str, default=None,
                                      help="Directory containing TPL dex versions")
    parser_kotlin_bucket.add_argument("-o", "--output-dir", type=str, default=None,
                                      help="Directory to write bucket pickles")
    parser_kotlin_bucket.add_argument("-t", "--threshold", type=float, default=0.8,
                                      help="Bucket support threshold")
    parser_kotlin_bucket.add_argument("-b", "--bucket", action="append", default=None,
                                      help="Specific bucket to build")
    parser_kotlin_bucket.add_argument("--overwrite", action="store_true",
                                      help="Overwrite existing bucket pickles")

    return parser.parse_args()


def jar_to_dex(libs_folder, lib_dex_folder):
    """用 D8 把 JAR 转成 DEX 文件。"""
    for file in os.listdir(libs_folder):
        target_dex = lib_dex_folder + "/" + file[: file.rfind(".")] + ".dex"
        if os.path.exists(target_dex):
            continue
        input_file = libs_folder + "/" + file
        tmp_file = f"{lib_dex_folder}/classes.dex"
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        cmd = (
            f"java -cp libs/d8.jar com.android.tools.r8.D8 "
            f"--lib libs/android.jar --output {lib_dex_folder} {input_file}"
        )
        print(cmd)
        os.system(cmd)
        if os.path.exists(tmp_file):
            os.rename(tmp_file, target_dex)
        else:
            raise Exception("Dex file not converted!")


def arr_to_jar(libs_folder):
    """把 AAR 文件解压为 JAR 文件。"""
    for file in os.listdir(libs_folder):
        if file.endswith(".aar"):
            os.rename(
                libs_folder + "/" + file,
                libs_folder + "/" + file[: file.rfind(".")] + ".zip",
            )
    for file in os.listdir(libs_folder):
        target_name = libs_folder + "/" + file[: file.rfind(".")] + ".jar"
        if os.path.exists(target_name):
            return
        if file.endswith(".zip"):
            zip_file = zipfile.ZipFile(libs_folder + "/" + file)
            zip_file.extract("classes.jar", ".")
            for f in os.listdir(libs_folder):
                if f == "classes.jar":
                    os.rename(libs_folder + "/" + f, target_name)
            zip_file.close()
            os.remove(libs_folder + "/" + file)


def main(
    lib_folder="libs",
    lib_dex_folder="libs_dex",
    apk_folder="apks",
    output_folder="outputs",
    processes=None,
    model="multiple",
):
    if model == "multiple":
        search_libs_in_app(
            os.path.abspath(lib_dex_folder),
            os.path.abspath(apk_folder),
            os.path.abspath(output_folder),
            processes,
        )
    elif model == "one":
        search_lib_in_app(
            os.path.abspath(lib_dex_folder),
            os.path.abspath(apk_folder),
            os.path.abspath(output_folder),
            processes,
        )


if __name__ == "__main__":
    args = parse_arguments()

    # ── 路径解析修复 ──────────────────────────────────────────────────────
    # 原版代码：对相对路径做二次拼接到 SYSTEM_DATA_DIR，但适配器已传入绝对路径，
    # 导致路径变成 /project/data//absolute/path/xxx 之类的无效路径。
    # 修复策略：
    #   - 如果路径已经是绝对路径，直接使用，不做任何拼接。
    #   - 如果是相对路径，才拼接到脚本所在目录的上级 data/ 目录。
    def _resolve_path(p: str | None) -> str | None:
        if p is None:
            return None
        if os.path.isabs(p):
            return p                                   # 已是绝对路径，直接用
        return os.path.join(SYSTEM_DATA_DIR, os.path.basename(p))  # 相对路径，拼到 data/

    if hasattr(args, "ld"):
        args.ld = _resolve_path(args.ld)
    if hasattr(args, "lf"):
        args.lf = _resolve_path(args.lf)

    clear_log()
    LOGGER = setup_logger()
    LOGGER.debug("args: %s", args)

    if getattr(args, "o", None) and not os.path.exists(args.o):
        os.makedirs(args.o)

    if args.subparser_name == "detect_one":
        main(
            lib_folder=args.lf,
            lib_dex_folder=args.ld,
            apk_folder=args.af,
            output_folder=args.o,
            processes=args.p,
            model="one",
        )
    elif args.subparser_name == "detect_all":
        main(
            lib_folder=args.lf,
            lib_dex_folder=args.ld,
            apk_folder=args.af,
            output_folder=args.o,
            processes=args.p,
            model="multiple",
        )
    elif args.subparser_name == "build_skeleton":
        from module.skeleton_builder import (
            DEFAULT_PICKLE_DIR,
            DEFAULT_SKELETON_DIR,
            build_skeleton_pickles,
        )

        pickle_dir = args.pickle_dir or DEFAULT_PICKLE_DIR
        output_dir = args.output_dir or DEFAULT_SKELETON_DIR
        written = build_skeleton_pickles(
            pickle_dir,
            output_dir,
            families=args.family,
            threshold=args.threshold,
            overwrite=args.overwrite,
        )
        for family, path in written.items():
            print(f"{family}: {path}")
    elif args.subparser_name == "build_jackson_bucket":
        from module.build_jackson_bucket import (
            DEFAULT_BUCKET_DIR,
            DEFAULT_PICKLE_DIR,
            DEFAULT_TPL_DEX_DIR,
            JACKSON_DATABIND,
            build_jackson_bucket_pickles,
        )

        written = build_jackson_bucket_pickles(
            pickle_dir=args.pickle_dir or DEFAULT_PICKLE_DIR,
            tpl_dex_dir=args.tpl_dex_dir or DEFAULT_TPL_DEX_DIR,
            output_dir=args.output_dir or DEFAULT_BUCKET_DIR,
            threshold=args.threshold,
            buckets=args.bucket,
            overwrite=args.overwrite,
        )
        for bucket, path in written.items():
            print(f"{JACKSON_DATABIND} {bucket}: {path}")
    elif args.subparser_name == "build_guava_bucket":
        from module.build_guava_bucket import (
            DEFAULT_BUCKET_DIR,
            DEFAULT_PICKLE_DIR,
            DEFAULT_TPL_DEX_DIR,
            GUAVA,
            build_guava_bucket_pickles,
        )

        written = build_guava_bucket_pickles(
            pickle_dir=args.pickle_dir or DEFAULT_PICKLE_DIR,
            tpl_dex_dir=args.tpl_dex_dir or DEFAULT_TPL_DEX_DIR,
            output_dir=args.output_dir or DEFAULT_BUCKET_DIR,
            threshold=args.threshold,
            buckets=args.bucket,
            overwrite=args.overwrite,
        )
        for bucket, path in written.items():
            print(f"{GUAVA} {bucket}: {path}")
    elif args.subparser_name == "build_kotlin_bucket":
        from module.build_kotlin_bucket import (
            DEFAULT_BUCKET_DIR,
            DEFAULT_PICKLE_DIR,
            DEFAULT_TPL_DEX_DIR,
            KOTLIN_STDLIB,
            build_kotlin_bucket_pickles,
        )

        written = build_kotlin_bucket_pickles(
            pickle_dir=args.pickle_dir or DEFAULT_PICKLE_DIR,
            tpl_dex_dir=args.tpl_dex_dir or DEFAULT_TPL_DEX_DIR,
            output_dir=args.output_dir or DEFAULT_BUCKET_DIR,
            threshold=args.threshold,
            buckets=args.bucket,
            overwrite=args.overwrite,
        )
        for bucket, path in written.items():
            print(f"{KOTLIN_STDLIB} {bucket}: {path}")
    else:
        LOGGER.debug("Detection mode input error!")
