"""Type stubs for the native asherah module.

These stubs document the API surface for IDE tooling (mypy, pyright,
pylance). The actual implementation lives in the Rust extension module
``_asherah.abi3.so``.
"""
from typing import Any, Awaitable, Callable, Optional, TypedDict, Union

# ─── Configuration types ────────────────────────────────────────────────────

class _LogEvent(TypedDict, total=False):
    """Structured log event passed to :func:`set_log_hook` callbacks.

    ``level`` is one of ``"trace"``, ``"debug"``, ``"info"``, ``"warn"``,
    ``"error"``. ``target`` is the source module string (typically the Rust
    module path that emitted the log). ``message`` is the formatted message.
    """

    level: str
    message: str
    target: str

class _MetricsTimingEvent(TypedDict):
    """Metrics event for timing measurements.

    ``type`` is one of ``"encrypt"``, ``"decrypt"``, ``"store"``, ``"load"``.
    ``duration_ns`` is nanoseconds.
    """

    type: str
    duration_ns: int

class _MetricsCacheEvent(TypedDict):
    """Metrics event for cache lifecycle.

    ``type`` is one of ``"cache_hit"``, ``"cache_miss"``, ``"cache_stale"``.
    ``name`` is the cache name (e.g. ``"session"``, ``"intermediate-key"``,
    ``"system-key"``).
    """

    type: str
    name: str

# ─── Module-level API (legacy / canonical compatibility) ────────────────────

def setup(config: Any) -> None:
    """Initialize the global Asherah instance.

    ``config`` is a dict (or any JSON-serializable object) using PascalCase
    keys: ``ServiceName``, ``ProductID``, ``Metastore``, ``KMS``, etc.

    Raises ``RuntimeError`` if Asherah is already configured (call
    :func:`shutdown` first) or if the config is invalid.

    Prefer :class:`SessionFactory` for new code — the static API uses a
    process-wide singleton and locks the metastore/KMS until shutdown.
    """

def shutdown() -> None:
    """Tear down the global Asherah instance, releasing the metastore
    and KMS clients. Idempotent — safe to call when already shut down."""

def get_setup_status() -> bool:
    """Return ``True`` when :func:`setup` has been called and
    :func:`shutdown` has not yet been called."""

def setenv(env_obj: Any) -> None:
    """Apply a dict of environment variables before :func:`setup`. Keys
    must be strings; values may be strings or ``None`` (a ``None`` value
    deletes the variable)."""

def encrypt_bytes(partition_id: str, data: bytes) -> str:
    """Encrypt ``data`` for ``partition_id``. Returns the
    ``DataRowRecord`` JSON envelope as a string.

    ``partition_id`` must be a non-empty string — ``None`` and ``""``
    are programming errors and raise.

    ``data`` must be ``bytes``. Empty ``bytes`` (``b""``) is valid and
    round-trips back to ``b""`` on decrypt. Do not short-circuit empty
    inputs — see ``docs/input-contract.md`` in the repository for why.
    """

def encrypt_string(partition_id: str, text: str) -> str:
    """UTF-8 string variant of :func:`encrypt_bytes`. Empty string is valid."""

def decrypt_bytes(partition_id: str, data_row_record: str) -> bytes:
    """Decrypt a ``DataRowRecord`` JSON string. Returns the original
    plaintext as ``bytes``. Length 0 if the original plaintext was empty.

    Raises if the JSON is malformed, the partition doesn't match, the
    parent key has been revoked, or the AEAD tag fails."""

def decrypt_string(partition_id: str, data_row_record: str) -> str:
    """UTF-8 string variant of :func:`decrypt_bytes`."""

def encrypt_bytes_async(partition_id: str, data: bytes) -> Awaitable[str]:
    """Async encrypt — returns an awaitable. Runs on Rust's tokio runtime
    (a native PyO3 coroutine), so the asyncio event loop is not blocked."""

def decrypt_bytes_async(
    partition_id: str, data_row_record: Union[str, bytes]
) -> Awaitable[bytes]:
    """Async decrypt — returns an awaitable. Runs on Rust's tokio runtime."""

# ─── Observability hooks ────────────────────────────────────────────────────

def set_metrics_hook(callback: Optional[Callable[[Any], None]] = ...) -> None:
    """Install a callback that receives metrics events for every
    encrypt/decrypt/store/load and key cache hit/miss/stale.

    The callback receives a single ``dict`` argument:

      - timing events: ``{"type": "encrypt"|"decrypt"|"store"|"load",
        "duration_ns": int}``
      - cache events: ``{"type": "cache_hit"|"cache_miss"|"cache_stale",
        "name": str}``

    Pass ``None`` to deregister. Metrics collection is enabled
    automatically when a hook is installed and disabled when cleared.

    The callback may fire from any thread (Rust tokio worker threads,
    DB driver threads). PyO3 acquires the GIL before invoking the
    callback, so the callback runs single-threaded from Python's
    perspective."""

def set_log_hook(callback: Optional[Callable[[Any], None]] = ...) -> None:
    """Install a callback that receives every log event from the Rust
    core (encrypt/decrypt path, metastore drivers, KMS clients).

    The callback receives a single ``dict`` argument with keys
    ``"level"`` (``"trace"|"debug"|"info"|"warn"|"error"``),
    ``"message"`` (the formatted log message), and ``"target"`` (the
    source module string).

    Pass ``None`` to deregister."""

def version() -> str:
    """Return the asherah package version string (e.g. ``"0.6.64"``)."""

# ─── Factory / Session API (recommended) ────────────────────────────────────

class SessionFactory:
    """Factory for creating per-partition :class:`Session` instances.

    Holding a long-lived factory is cheaper than calling
    :func:`setup` / :func:`shutdown` repeatedly, and makes session
    isolation explicit in code.

    Constructed without arguments — reads configuration from the
    standard environment variables (``SERVICE_NAME``, ``PRODUCT_ID``,
    ``KMS``, ``Metastore``, ``STATIC_MASTER_KEY_HEX``, etc.). Use
    :func:`setenv` first if you need to set them programmatically.
    """

    def __init__(self) -> None: ...
    @staticmethod
    def from_env() -> "SessionFactory":
        """Same as the no-argument constructor — provided for parity
        with the canonical Go SDK's ``FromEnv``."""
    def get_session(self, partition_id: str) -> "Session":
        """Get a session for the given partition. Sessions returned for
        the same partition share the underlying intermediate key;
        different partitions are cryptographically isolated.

        ``partition_id`` must be non-empty."""
    def close(self) -> None:
        """Release native resources. After ``close()``, calls to
        :meth:`get_session` raise."""
    def __enter__(self) -> "SessionFactory": ...
    def __exit__(
        self,
        ty: Optional[type] = ...,
        value: Optional[BaseException] = ...,
        tb: Optional[Any] = ...,
    ) -> None: ...

class Session:
    """Per-partition encrypt/decrypt session. Created via
    :meth:`SessionFactory.get_session`. Pair with :meth:`close` (or use
    as a context manager) to release native resources promptly."""

    def encrypt_bytes(self, data: bytes) -> str:
        """Encrypt ``bytes`` and return the ``DataRowRecord`` JSON
        string. Empty ``bytes`` is valid."""
    def encrypt_text(self, text: str) -> str:
        """UTF-8 string variant of :meth:`encrypt_bytes`. Empty string
        is valid."""
    def decrypt_bytes(self, data_row_record: str) -> bytes:
        """Decrypt a ``DataRowRecord`` JSON string and return the
        plaintext as ``bytes``."""
    def decrypt_text(self, data_row_record: str) -> str:
        """UTF-8 string variant of :meth:`decrypt_bytes`."""
    def encrypt_bytes_async(self, data: bytes) -> Awaitable[str]:
        """Async encrypt — returns an awaitable. Runs on the Rust tokio
        runtime as a native PyO3 coroutine; the asyncio event loop is
        not blocked."""
    def decrypt_bytes_async(
        self, data_row_record: Union[str, bytes]
    ) -> Awaitable[bytes]:
        """Async decrypt — returns an awaitable. Runs on the Rust tokio
        runtime."""
    def close(self) -> None:
        """Release native resources."""
    def __enter__(self) -> "Session": ...
    def __exit__(
        self,
        ty: Optional[type] = ...,
        value: Optional[BaseException] = ...,
        tb: Optional[Any] = ...,
    ) -> None: ...
