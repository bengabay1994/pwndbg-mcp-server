"""
GDB Session Manager for pwndbg-mcp.

This module handles the lifecycle of a GDB session with pwndbg loaded,
using pexpect for PTY-based interaction.
"""

import re
import pexpect
import shutil
from typing import Optional
from pydantic import BaseModel
from enum import Enum


class SessionState(str, Enum):
    """Current state of the debugging session."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    STOPPED = "stopped"
    EXITED = "exited"


class SessionInfo(BaseModel):
    """Information about the current debugging session."""
    state: SessionState
    binary_path: Optional[str] = None
    pid: Optional[int] = None
    is_attached: bool = False


class GDBSession:
    """
    Manages a single GDB session with pwndbg.
    
    Uses pexpect to spawn GDB as a subprocess and communicate via PTY.
    This allows full compatibility with pwndbg's colored terminal output.
    """
    
    # Regex pattern to match the pwndbg prompt
    # pwndbg typically shows: pwndbg> or similar
    PROMPT_PATTERNS = [
        r'pwndbg>',
        r'\(gdb\)',
        r'>>>',  # Python prompt if in pwndbg Python mode
    ]
    
    # ANSI escape code pattern for stripping colors
    ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    
    def __init__(self, gdb_path: str = "gdb", timeout: int = 30):
        """
        Initialize the GDB session manager.
        
        Args:
            gdb_path: Path to the GDB executable (default: "gdb")
            timeout: Default timeout for commands in seconds
        """
        self.gdb_path = gdb_path
        self.timeout = timeout
        self._process: Optional[pexpect.spawn] = None
        self._state = SessionState.NOT_STARTED
        self._binary_path: Optional[str] = None
        self._pid: Optional[int] = None
        self._is_attached = False
        
    @property
    def is_active(self) -> bool:
        """Check if there's an active GDB session."""
        return self._process is not None and self._process.isalive()
    
    @property
    def info(self) -> SessionInfo:
        """Get current session information."""
        return SessionInfo(
            state=self._state,
            binary_path=self._binary_path,
            pid=self._pid,
            is_attached=self._is_attached,
        )
    
    def _wait_for_prompt(self, timeout: Optional[int] = None) -> str:
        """
        Wait for the GDB/pwndbg prompt and return all output before it.
        
        Args:
            timeout: Timeout in seconds (uses default if None)
            
        Returns:
            The output received before the prompt
        """
        if not self._process:
            raise RuntimeError("No active GDB session")
            
        timeout = timeout or self.timeout
        
        # Compile patterns for pexpect
        patterns = [re.compile(p) for p in self.PROMPT_PATTERNS]
        
        try:
            self._process.expect(patterns, timeout=timeout)
            output = self._process.before
            if isinstance(output, bytes):
                output = output.decode('utf-8', errors='replace')
            return output
        except pexpect.TIMEOUT:
            raise TimeoutError(f"GDB command timed out after {timeout} seconds")
        except pexpect.EOF:
            self._state = SessionState.EXITED
            raise RuntimeError("GDB process terminated unexpectedly")
    
    def _verify_pwndbg_loaded(self) -> bool:
        """
        Verify that pwndbg is loaded by trying a pwndbg-specific command.

        Returns:
            True if pwndbg is loaded, False otherwise
        """
        try:
            # Try a simple pwndbg command like 'pwndbg' or check for context
            output = self.execute("help context", timeout=5)
            # If the command exists, pwndbg is loaded
            return "Undefined command" not in output and "not defined" not in output.lower()
        except Exception:
            return False

    def _configure_heap_version(self) -> None:
        """
        Try to auto-configure the glibc version for heap commands.

        This helps pwndbg resolve heap symbols. Silently fails if detection doesn't work.
        """
        try:
            import subprocess
            # Try to detect glibc version from ldd
            result = subprocess.run(
                ["ldd", "--version"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                # Parse version from output like "ldd (Debian GLIBC 2.42-5) 2.42"
                first_line = result.stdout.split('\n')[0]
                # Look for version pattern like "2.42" or "2.31"
                import re
                version_match = re.search(r'(\d+\.\d+)', first_line)
                if version_match:
                    version = version_match.group(1)
                    # Set in pwndbg - this may help heap commands work
                    self.execute(f"set glibc {version}", timeout=2)
        except Exception:
            # Not critical if this fails - heap commands may still work with debug symbols
            pass

    def start(self, binary_path: Optional[str] = None, args: Optional[list[str]] = None) -> str:
        """
        Start a new GDB session with pwndbg loaded.

        Tries multiple methods to load pwndbg:
        1. Use 'pwndbg' binary directly (modern installation)
        2. Use 'gdb' and rely on .gdbinit to load pwndbg
        3. Error if neither works

        Args:
            binary_path: Optional path to the binary to debug
            args: Optional arguments for GDB

        Returns:
            Initial GDB output

        Raises:
            RuntimeError: If pwndbg cannot be loaded
        """
        if self.is_active:
            raise RuntimeError("A GDB session is already active. Close it first.")

        # Try method 1: Use 'pwndbg' binary directly
        pwndbg_binary = shutil.which("pwndbg")
        gdb_binary = shutil.which(self.gdb_path)

        attempts = []

        if pwndbg_binary:
            attempts.append(("pwndbg", pwndbg_binary, "pwndbg binary (modern installation)"))

        if gdb_binary:
            attempts.append(("gdb", gdb_binary, "gdb with .gdbinit"))

        if not attempts:
            raise RuntimeError(
                "Neither 'pwndbg' nor 'gdb' binary found in PATH. "
                "Please install pwndbg: https://pwndbg.re/stable/setup"
            )

        last_error = None

        for name, binary_path_to_use, description in attempts:
            try:
                # Build the command
                cmd_args = [binary_path_to_use, "-q"]  # -q for quiet mode (no banner)

                if binary_path:
                    cmd_args.append(binary_path)
                    self._binary_path = binary_path

                if args:
                    cmd_args.extend(args)

                # Spawn GDB with a PTY
                self._process = pexpect.spawn(
                    cmd_args[0],
                    cmd_args[1:],
                    encoding='utf-8',
                    timeout=self.timeout,
                    dimensions=(24, 200),  # Large width to avoid line wrapping
                )

                # Wait for initial prompt
                output = self._wait_for_prompt()
                self._state = SessionState.STOPPED

                # Verify pwndbg is actually loaded
                if self._verify_pwndbg_loaded():
                    # Success! pwndbg is loaded
                    # Try to auto-configure glibc version for heap commands
                    self._configure_heap_version()
                    return output
                else:
                    # pwndbg not loaded with this method
                    self.close()
                    last_error = f"Started {description} but pwndbg was not loaded"
                    continue

            except Exception as e:
                # Clean up failed attempt
                if self._process:
                    self._process.close(force=True)
                    self._process = None
                last_error = f"Failed to start {description}: {str(e)}"
                continue

        # If we get here, all attempts failed
        error_msg = (
            "Failed to start GDB with pwndbg loaded.\n\n"
            "Attempted methods:\n"
        )
        for name, _, description in attempts:
            error_msg += f"  - {description}\n"

        if last_error:
            error_msg += f"\nLast error: {last_error}\n"

        error_msg += (
            "\nPlease ensure pwndbg is installed correctly:\n"
            "  1. Modern method: curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb\n"
            "  2. Manual method: https://pwndbg.re/stable/setup\n"
        )

        raise RuntimeError(error_msg)
    
    def execute(self, command: str, timeout: Optional[int] = None, strip_ansi: bool = True) -> str:
        """
        Execute a GDB/pwndbg command and return the output.
        
        Args:
            command: The command to execute
            timeout: Optional timeout override
            strip_ansi: Whether to strip ANSI color codes from output
            
        Returns:
            The command output
        """
        if not self.is_active:
            raise RuntimeError("No active GDB session")
        
        # Send the command
        self._process.sendline(command)
        
        # Wait for prompt and get output
        output = self._wait_for_prompt(timeout)
        
        # Remove the echoed command from the output
        lines = output.split('\n')
        if lines and command in lines[0]:
            lines = lines[1:]
        output = '\n'.join(lines)
        
        # Strip ANSI codes if requested
        if strip_ansi:
            output = self.ANSI_ESCAPE.sub('', output)
        
        return output.strip()
    
    def run(self, args: Optional[str] = None) -> str:
        """
        Run the loaded binary.
        
        Args:
            args: Optional arguments to pass to the binary
            
        Returns:
            Output from GDB
        """
        cmd = "run"
        if args:
            cmd += f" {args}"
        
        output = self.execute(cmd)
        self._state = SessionState.RUNNING
        return output
    
    def attach(self, target: str | int) -> str:
        """
        Attach to a running process.
        
        Args:
            target: PID (int) or process name (str) to attach to
            
        Returns:
            Output from GDB
        """
        if not self.is_active:
            # Start GDB first if not already running
            self.start()
        
        # Use pwndbg's attachp command which handles both PID and name
        output = self.execute(f"attachp {target}")
        
        if isinstance(target, int):
            self._pid = target
        
        self._is_attached = True
        self._state = SessionState.STOPPED
        
        return output
    
    def detach(self) -> str:
        """
        Detach from the current process.
        
        Returns:
            Output from GDB
        """
        output = self.execute("detach")
        self._is_attached = False
        self._pid = None
        self._state = SessionState.STOPPED
        return output
    
    def continue_execution(self) -> str:
        """
        Continue program execution.
        
        Returns:
            Output from GDB
        """
        output = self.execute("continue")
        self._state = SessionState.RUNNING
        return output
    
    def interrupt(self) -> str:
        """
        Interrupt the running program (send Ctrl+C).
        
        Returns:
            Output from GDB
        """
        if not self._process:
            raise RuntimeError("No active GDB session")
        
        self._process.sendcontrol('c')
        output = self._wait_for_prompt()
        self._state = SessionState.STOPPED
        return output
    
    def close(self) -> None:
        """
        Close the GDB session gracefully.
        """
        if self._process:
            try:
                self._process.sendline("quit")
                self._process.expect(pexpect.EOF, timeout=5)
            except (pexpect.TIMEOUT, pexpect.EOF):
                pass
            finally:
                self._process.close(force=True)
                self._process = None
        
        self._state = SessionState.NOT_STARTED
        self._binary_path = None
        self._pid = None
        self._is_attached = False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False


# Global session instance (single session design)
_session: Optional[GDBSession] = None


def get_session() -> GDBSession:
    """
    Get the global GDB session instance.
    
    Creates a new session if one doesn't exist.
    """
    global _session
    if _session is None:
        _session = GDBSession()
    return _session


def close_session() -> None:
    """
    Close and clear the global GDB session.
    """
    global _session
    if _session is not None:
        _session.close()
        _session = None
