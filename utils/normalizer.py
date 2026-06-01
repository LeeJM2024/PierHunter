from __future__ import annotations

import re


# 用来匹配常见库文件后缀名。`re.IGNORECASE` 表示忽略大小写，所以 `.DEX` 这类写法也能匹配。
_EXT_PATTERN = re.compile(r"\.(dex|jar|aar)$", re.IGNORECASE)

# 用来匹配“名称 + 版本号”的库标识形式。例如：`okhttp_2.7.5`
_VERSION_SUFFIX_PATTERN = re.compile(
    r"^(?P<prefix>.+?)[_-](?P<version>\d[\w.\-+]*)$"
)

def _strip_known_extension(raw_lib: str) -> str:
    # 去掉输入字符串两端的空白字符后，再删除结尾处已知的库文件后缀（如 .dex / .jar / .aar）。
    return _EXT_PATTERN.sub("", raw_lib.strip())


def _canonicalize_prefix(prefix: str) -> str:
    # 先去掉前后可能存在的分隔符和空格，
    prefix = prefix.strip("._- ")
    if not prefix:
        return prefix
    # 如果字符串里同时包含下划线和点号，这里尝试把最后一个下划线右边的部分当成 artifact。
    if "_" in prefix and "." in prefix:
        left, right = prefix.rsplit("_", 1)
        # 如果右边部分里不包含冒号，也不包含点号，这时把它规范化成 Maven 风格的 `group:artifact`。
        if ":" not in right and "." not in right:
            return f"{left}:{right}"
    # 如果前面的特殊下划线规则没有命中，但字符串里包含点号，那么再尝试把最后一个点号作为 group 和 artifact 的分隔点。
    if "." in prefix:
        # 从右边按最后一个点拆分：左边作为 group，右边作为 artifact。
        group, artifact = prefix.rsplit(".", 1)
        # 只有当两边都非空时，才返回规范化结果，
        if group and artifact:
            return f"{group}:{artifact}"
    return prefix


def normalize_libhunter_lib(raw_lib: str) -> dict:
    # 解析 LibHunter 输出的原始库标识。
    # 这里基于以下约定进行处理：
    # LibHunter 通常输出的格式是 `<group>.<artifact>_<version>.dex`
    # 有些库会在 group 和 artifact 之间使用下划线，例如
    # `com.squareup.okhttp_okhttp_2.7.5.dex`
    # 如果无法提取版本号，则保留原始库名，并返回 `version=None`，
    raw_lib = raw_lib.strip()

    # 去掉结尾处已知的扩展名，只保留核心名称部分。例如把 `xxx.dex` 变成 `xxx`。
    stem = _strip_known_extension(raw_lib)
    version = None
    prefix = stem
    # 尝试从字符串末尾解析版本号。
    match = _VERSION_SUFFIX_PATTERN.match(stem)
    if match:
        prefix = match.group("prefix")
        version = match.group("version")

    # 对库名前缀做一次规范化，
    library_name = _canonicalize_prefix(prefix)

    # 返回统一结构的字典结果：
    return {
        "raw_lib": raw_lib, # 原始名字
        "library_name": library_name or raw_lib,   #规范化后库名
        "version": version, # 版本号
    }


def build_library_aliases(*values: str | None) -> set[str]:
    # 用集合收集别名，自动去重。
    aliases: set[str] = set()

    for value in values:
        if not value:
            continue

        normalized = _strip_known_extension(value).strip().lower()


        if not normalized:
            continue

        # 原始规范化结果本身先加入别名集合。
        aliases.add(normalized)

        # 把下划线替换成冒号，兼容 `group_artifact` 形式。
        aliases.add(normalized.replace("_", ":"))

        # 把点号替换成冒号，兼容 `group.artifact` 与 `group:artifact` 的对照。
        aliases.add(normalized.replace(".", ":"))

        # 把下划线替换成点号，兼容另一类命名差异。
        aliases.add(normalized.replace("_", "."))

        # 把冒号替换成点号，方便与 Java/Maven 风格库名互相映射。
        aliases.add(normalized.replace(":", "."))

        # 把冒号替换成下划线，兼容某些工具导出的下划线命名。
        aliases.add(normalized.replace(":", "_"))

        # 如果名字中包含冒号，说明它可能已经是 `group:artifact` 形式，
        # 这时额外把最后一段 artifact 单独提取出来作为别名。
        if ":" in normalized:
            _, artifact = normalized.rsplit(":", 1)
            aliases.add(artifact)

        # 如果没有冒号但有点号，就把最后一个点后的部分提取出来，
        # 例如从 `com.squareup.okhttp` 中提取 `okhttp`。
        elif "." in normalized:
            aliases.add(normalized.rsplit(".", 1)[-1])

        # 如果前两种形式都没有，但包含下划线，
        # 也尝试取最后一个下划线后的部分作为可能的 artifact 名。
        elif "_" in normalized:
            aliases.add(normalized.rsplit("_", 1)[-1])

    # 最后统一清理每个别名两端可能残留的分隔符和空格，
    # 同时过滤掉清理后变成空字符串的结果。
    return {alias.strip("._:- ") for alias in aliases if alias.strip("._:- ")}
