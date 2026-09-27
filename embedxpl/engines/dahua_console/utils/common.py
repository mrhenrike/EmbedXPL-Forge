"""General-purpose utilities."""
import os
import platform
import queue
import signal
import subprocess
from concurrent.futures import ThreadPoolExecutor


def os_check() -> str:
    """Detect and return the current operating system name."""
    _os = platform.system().lower()
    if _os == 'windows':
        return 'windows'
    elif _os == 'linux':
        return 'linux'
    elif _os == 'darwin':
        return 'mac'
    return 'other'


def singleton(cls, *args, **kwargs):
    """Class decorator that enforces the singleton pattern."""
    instance = {}
    def wrapper(*args, **kwargs):
        if cls not in instance:
            instance[cls] = cls(*args, **kwargs)
        return instance[cls]
    return wrapper


class IngramThreadPool(ThreadPoolExecutor):
    """
    ThreadPoolExecutor with a bounded work queue.
    The default queue is unbounded and can exhaust memory on large target sets.
    """

    def __init__(self, max_workers=None, thread_name_prefix=''):
        super().__init__(max_workers, thread_name_prefix)
        self._work_queue = queue.Queue(self._max_workers * 2)


def run_cmd(cmd_string, timeout=60):
    """
    Run a shell command and return (exit_code, output).

    Uses os.killpg to reliably kill all child processes on timeout.
    """
    p = subprocess.Popen(
        cmd_string,
        stderr=subprocess.STDOUT,
        stdout=subprocess.PIPE,
        shell=True,
        close_fds=True,
        start_new_session=True,
    )

    fmt = 'gbk' if os_check() == 'windows' else 'utf-8'

    try:
        msg, _ = p.communicate(timeout=timeout)
        code = p.poll()
        if code:
            return 1, '[Error] ' + msg.decode(fmt)
        return 0, msg.decode(fmt)
    except subprocess.TimeoutExpired:
        # Kill the entire process group - plain p.kill() may leave child processes alive
        p.kill()
        p.terminate()
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except Exception:
            pass
        outs, _ = p.communicate()
        return 0, outs.decode(fmt)
    except Exception as e:
        return 1, f'[ERROR] Unknown error: {e}'
