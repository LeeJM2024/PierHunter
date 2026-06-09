"""Unified subprocess runner with streaming output, heartbeat detection,
and optional per-OS memory limits."""
from __future__ import annotations

import platform
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional


class CommandExecutionError(RuntimeError):
    """Raised when a command exits with a non-zero return code."""

    def __init__(self, message: str, returncode: int, stdout: str, stderr: str):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class CommandResult:
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str
    hung: bool = False          # 【新增】True 表示心跳超时被强制 kill
    timed_out: bool = False


# ── 【新增】内存限制辅助函数（仅 Linux）────────────────────────
def _make_memory_limiter(max_bytes: int) -> Optional[Callable]:
    """
    返回一个可用作 subprocess.Popen(preexec_fn=...) 的函数。
    仅在 Linux 下生效；其他平台返回 None（Popen 会忽略 None）。
    max_bytes: 虚拟地址空间上限，建议 4 * 1024**3（4 GB）。
    """
    if platform.system() != "Linux":
        return None

    def _limit():
        import resource  # 只在子进程内 import，避免 Windows 报错
        resource.setrlimit(
            resource.RLIMIT_AS,
            (max_bytes, max_bytes),
        )

    return _limit


# 默认内存上限：4 GB
_DEFAULT_MEM_LIMIT = 4 * 1024 ** 3


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
    stream_output: bool = False,
    raise_on_error: bool = False,
    on_stdout_line: Optional[Callable[[str], None]] = None,
    on_stderr_line: Optional[Callable[[str], None]] = None,
    # 【新增参数】
    heartbeat_timeout: int = 60,
    memory_limit_bytes: int = _DEFAULT_MEM_LIMIT,
) -> CommandResult:
    """
    Run an external command and capture output.

    Parameters
    ----------
    cmd                  : Command and arguments list.
    cwd                  : Working directory for the subprocess.
    timeout              : Maximum seconds to wait for the process to finish.
    env                  : Full environment mapping; None inherits current env.
    stream_output        : If True, echo stdout/stderr to console in real time.
    raise_on_error       : If True, raise CommandExecutionError on non-zero exit.
    heartbeat_timeout    : 【新增】Seconds of silence (no new output) before the
                           process is considered hung and killed. 0 = disabled.
    memory_limit_bytes   : 【新增】Virtual address space cap for the child process
                           (Linux only). Default 4 GB. 0 = disabled.

    Returns
    -------
    CommandResult – includes a `hung=True` flag when killed by heartbeat.
    """
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    # 【新增】共享的"最后活跃时间戳"，由 reader 线程负责刷新
    last_activity: List[float] = [time.monotonic()]
    hung_flag: List[bool] = [False]
    timed_out_flag: List[bool] = [False]

    def _reader(
        pipe,
        collector: List[str],
        do_print: bool,
        on_line: Optional[Callable[[str], None]],
    ) -> None:
        for raw in pipe:
            line = raw.rstrip("\n")
            collector.append(line)
            last_activity[0] = time.monotonic()   # 刷新心跳时间
            if on_line is not None:
                on_line(line)
            if do_print:
                print(line, flush=True)

    # 【新增】内存限制 preexec_fn
    preexec = None
    if memory_limit_bytes > 0:
        preexec = _make_memory_limiter(memory_limit_bytes)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            preexec_fn=preexec,   # 【新增】内存限制
        )

        t_out = threading.Thread(
            target=_reader,
            args=(proc.stdout, stdout_lines, stream_output, on_stdout_line),
            daemon=True,
        )
        t_err = threading.Thread(
            target=_reader,
            args=(proc.stderr, stderr_lines, stream_output, on_stderr_line),
            daemon=True,
        )
        t_out.start()
        t_err.start()

        # ── 【新增】心跳监控线程 ──────────────────────────────
        def _heartbeat_watcher():
            """若进程超过 heartbeat_timeout 秒无任何输出则强制终止。"""
            if heartbeat_timeout <= 0:
                return
            while proc.poll() is None:          # 进程还在运行
                time.sleep(5)                    # 每 5 秒检查一次
                silence = time.monotonic() - last_activity[0]
                if silence >= heartbeat_timeout:
                    print(
                        f"[runner] Heartbeat timeout ({heartbeat_timeout}s silence). "
                        f"Killing PID {proc.pid}.",
                        flush=True,
                    )
                    hung_flag[0] = True
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    return

        watcher = threading.Thread(target=_heartbeat_watcher, daemon=True)
        watcher.start()
        # ─────────────────────────────────────────────────────

        proc.wait(timeout=timeout)
        t_out.join()
        t_err.join()
        watcher.join(timeout=2)

    except subprocess.TimeoutExpired:
        timed_out_flag[0] = True
        proc.kill()
        proc.wait()
        t_out.join(timeout=2)
        t_err.join(timeout=2)
    except FileNotFoundError as exc:
        raise CommandExecutionError(
            f"Executable not found: {cmd[0]}",
            returncode=-1,
            stdout="",
            stderr=str(exc),
        ) from exc

    result = CommandResult(
        cmd=cmd,
        returncode=proc.returncode,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        hung=hung_flag[0],           # 【新增】
        timed_out=timed_out_flag[0],
    )

    if raise_on_error and result.returncode != 0 and not result.hung:
        raise CommandExecutionError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    return result
