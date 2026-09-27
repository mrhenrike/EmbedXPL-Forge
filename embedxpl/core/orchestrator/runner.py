# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Exploit Runner - Execute compiled binaries with resource controls.

Provides ExploitRunner for executing compiled exploit binaries with
configurable timeout, stdout/stderr capture, exit code handling, and
automatic cleanup of temporary files.

Version: 1.0.0
"""

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from embedxpl.core.orchestrator.artifact import CompiledArtifact


_PROJECT_TMP = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp"
)


@dataclass
class RunResult:
    """Result of an exploit binary execution.

    Attributes:
        exit_code: Process exit code (-1 if killed or error).
        stdout: Captured standard output.
        stderr: Captured standard error.
        elapsed: Wall-clock execution time in seconds.
        timed_out: Whether execution was terminated by timeout.
        signal_name: Signal that terminated the process, if any.
        artifact: Reference to the CompiledArtifact that was executed.
        pid: Process ID of the executed binary.
    """

    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    elapsed: float = 0.0
    timed_out: bool = False
    signal_name: str = ""
    artifact: Optional[CompiledArtifact] = None
    pid: int = 0

    @property
    def success(self) -> bool:
        """Return True if execution completed with exit code 0."""
        return self.exit_code == 0 and not self.timed_out


class ExploitRunner:
    """Execute compiled exploit binaries with timeout and capture.

    Runs a CompiledArtifact binary as a subprocess with configurable
    timeout, captures stdout/stderr, handles exit codes and signals,
    and cleans up temporary files.

    Args:
        default_timeout: Default execution timeout in seconds.
        working_dir: Working directory for the subprocess.
            Defaults to project .tmp/runs/.
        max_output_size: Maximum bytes to capture per stream (stdout/stderr).
    """

    def __init__(self, default_timeout: int = 30,
                 working_dir: str = "",
                 max_output_size: int = 1048576):
        self._default_timeout = default_timeout
        self._working_dir = working_dir or os.path.join(_PROJECT_TMP, "runs")
        self._max_output = max_output_size
        os.makedirs(self._working_dir, exist_ok=True)

    @property
    def working_dir(self) -> str:
        """Return the working directory for subprocess execution."""
        return self._working_dir

    def _validate_artifact(self, artifact: CompiledArtifact) -> None:
        """Validate that the artifact binary exists and is executable.

        Args:
            artifact: CompiledArtifact to validate.

        Raises:
            FileNotFoundError: If binary does not exist.
            PermissionError: If binary is not executable (POSIX).
        """
        if not os.path.isfile(artifact.binary_path):
            raise FileNotFoundError(
                "Binary not found: {}".format(artifact.binary_path)
            )
        if os.name != "nt" and not os.access(artifact.binary_path, os.X_OK):
            try:
                os.chmod(artifact.binary_path, 0o755)
            except OSError as exc:
                raise PermissionError(
                    "Cannot set executable permission: {}".format(exc)
                )

    def _signal_name(self, returncode: int) -> str:
        """Map negative return code to signal name (POSIX)."""
        if returncode >= 0 or os.name == "nt":
            return ""
        sig_num = -returncode
        try:
            return signal.Signals(sig_num).name
        except (ValueError, AttributeError):
            return "SIG{}".format(sig_num)

    def run(self, artifact: CompiledArtifact,
            args: Optional[list] = None,
            timeout: Optional[int] = None,
            env: Optional[dict] = None,
            stdin_data: Optional[str] = None) -> RunResult:
        """Execute a compiled artifact binary.

        Args:
            artifact: CompiledArtifact with the binary to execute.
            args: Command-line arguments to pass to the binary.
            timeout: Execution timeout in seconds. Uses default if None.
            env: Environment variables for the subprocess.
            stdin_data: Data to feed to stdin.

        Returns:
            RunResult with captured output and execution metadata.
        """
        self._validate_artifact(artifact)

        effective_timeout = timeout if timeout is not None else self._default_timeout
        cmd = [artifact.binary_path] + (args or [])

        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)

        result = RunResult(artifact=artifact)
        start_time = time.time()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
                cwd=self._working_dir,
                env=proc_env,
            )
            result.pid = proc.pid

            try:
                stdout_bytes, stderr_bytes = proc.communicate(
                    input=stdin_data.encode("utf-8") if stdin_data else None,
                    timeout=effective_timeout,
                )
                result.exit_code = proc.returncode
                result.stdout = stdout_bytes[:self._max_output].decode(
                    "utf-8", errors="replace"
                )
                result.stderr = stderr_bytes[:self._max_output].decode(
                    "utf-8", errors="replace"
                )
                result.signal_name = self._signal_name(proc.returncode)

            except subprocess.TimeoutExpired:
                self._terminate_process(proc)
                stdout_bytes, stderr_bytes = proc.communicate(timeout=5)
                result.timed_out = True
                result.exit_code = -1
                result.stdout = stdout_bytes[:self._max_output].decode(
                    "utf-8", errors="replace"
                ) if stdout_bytes else ""
                result.stderr = stderr_bytes[:self._max_output].decode(
                    "utf-8", errors="replace"
                ) if stderr_bytes else ""

        except FileNotFoundError:
            result.exit_code = 127
            result.stderr = "Binary not found: {}".format(artifact.binary_path)
        except PermissionError:
            result.exit_code = 126
            result.stderr = "Permission denied: {}".format(artifact.binary_path)
        except OSError as exc:
            result.exit_code = -1
            result.stderr = "Execution error: {}".format(exc)

        result.elapsed = time.time() - start_time
        return result

    def _terminate_process(self, proc: subprocess.Popen) -> None:
        """Gracefully terminate a process, escalating to SIGKILL."""
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except (OSError, ProcessLookupError):
            pass

    def run_with_retry(self, artifact: CompiledArtifact,
                       args: Optional[list] = None,
                       retries: int = 2,
                       timeout: Optional[int] = None) -> RunResult:
        """Execute with automatic retry on failure.

        Args:
            artifact: CompiledArtifact to execute.
            args: Command-line arguments.
            retries: Maximum number of retry attempts.
            timeout: Per-attempt timeout.

        Returns:
            RunResult from the first successful attempt, or the last failure.
        """
        last_result = None
        for attempt in range(1 + retries):
            result = self.run(artifact, args=args, timeout=timeout)
            if result.success:
                return result
            last_result = result
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
        return last_result

    def cleanup_runs(self) -> int:
        """Remove temporary files from the runs directory.

        Returns:
            Number of files removed.
        """
        count = 0
        if not os.path.isdir(self._working_dir):
            return count
        for entry in os.listdir(self._working_dir):
            entry_path = os.path.join(self._working_dir, entry)
            if os.path.isfile(entry_path):
                try:
                    os.unlink(entry_path)
                    count += 1
                except OSError:
                    pass
        return count
