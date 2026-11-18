"""
Restricted execution of LLM-generated Plotly code.

``VannaBase.get_plotly_figure`` runs Python code written by the LLM. The LLM
output can be steered through prompt injection (in the question, the query
results or the training data), so running that code with ``exec`` and the
full module globals allowed arbitrary code execution on the host
(CVE-2024-5565, CVE-2024-5826, vanna-ai/vanna#1062).

The code is now validated before it runs:

* only a small set of statements and expressions is allowed (no function or
  class definitions, ``while``, ``try``, ``with``, ``global`` ...);
* names and attributes starting with ``__`` / ``_`` are rejected, as are
  attributes that read or write files, evaluate strings or expose
  interpreter internals;
* imports are limited to Plotly, pandas and NumPy, which are exposed through
  read-only proxies that hide private names, I/O helpers and submodules;
* the code runs with a minimal set of builtins (no ``open``, ``eval``,
  ``exec``, ``getattr``, ``__import__`` ...);
* methods that call another method by name (``apply``, ``agg``, ...) may only
  be called directly with literal arguments, never stored in a variable or
  passed around, and Plotly trendline options are checked when the chart
  function runs.

This is defence in depth, not an operating-system sandbox. Applications that
let untrusted users trigger chart generation should still run with least
privilege.
"""

import ast
import builtins
import functools
import inspect
import string
import types
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.subplots


class UnsafePlotlyCodeError(ValueError):
    """Raised when generated Plotly code does not pass validation."""


# Attribute names that write files, evaluate strings, import modules by name
# or expose interpreter internals.
_BLOCKED_NAMES = frozenset(
    {
        "eval",
        "query",
        "plot",
        "style",
        "tofile",
        "dump",
        "ctypes",
        "mro",
        # Open a browser or write HTML files (``fig.show(renderer=...)``).
        "show",
        # Import a plotting backend module named by the ``backend`` argument.
        "hist",
        "boxplot",
    }
)

# Module-level functions that read or write files, change global options or
# run test suites. They are hidden from the module proxies below.
_HIDDEN_MODULE_NAMES = frozenset(
    {
        "options",
        "set_option",
        "get_option",
        "reset_option",
        "describe_option",
        "option_context",
        "load",
        "save",
        "savez",
        "savez_compressed",
        "savetxt",
        "loadtxt",
        "genfromtxt",
        "fromfile",
        "fromregex",
        "memmap",
        "DataSource",
        "ExcelFile",
        "ExcelWriter",
        "HDFStore",
        "test",
    }
)

# "_" covers private and dunder attributes; the others cover pandas/NumPy/Plotly
# readers and writers and frame/code/traceback internals.
_BLOCKED_PREFIXES = (
    "_",
    "read_",
    "write_",
    "to_",
    "gi_",
    "cr_",
    "ag_",
    "f_",
    "tb_",
    "co_",
)

# Conversions that are commonly used in chart code and do not touch files.
_ALLOWED_TO_NAMES = frozenset(
    {
        "to_datetime",
        "to_numeric",
        "to_timedelta",
        "to_list",
        "to_dict",
        "to_numpy",
        "to_frame",
        "to_period",
        "to_timestamp",
        "to_pydatetime",
    }
)

# Methods that call a method of the object when given its name as a string,
# e.g. ``df.apply("to_csv", path_or_buf=...)``.
_DISPATCH_METHODS = frozenset({"apply", "agg", "aggregate", "transform"})
_DISPATCH_KEYWORDS = frozenset({"trendline_options", "aggfunc"})

# Methods of rolling/expanding/ewm windows that Plotly trendlines may call by
# name through ``trendline_options={"function": ...}``.
_TRENDLINE_FUNCTIONS = frozenset(
    {
        "mean",
        "median",
        "sum",
        "min",
        "max",
        "std",
        "var",
        "sem",
        "count",
        "skew",
        "kurt",
        "quantile",
        "rank",
    }
)

# Attributes that chart code may assign to, e.g. ``df.columns = [...]``.
_ASSIGNABLE_ATTRIBUTES = frozenset({"columns", "index", "name", "names"})

_SAFE_BUILTIN_NAMES = (
    "abs",
    "all",
    "any",
    "bool",
    "dict",
    "enumerate",
    "filter",
    "float",
    "frozenset",
    "int",
    "isinstance",
    "len",
    "list",
    "map",
    "max",
    "min",
    "print",
    "range",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
)

# Names that must keep their meaning because the checks below rely on them.
_PROTECTED_NAMES = frozenset(_SAFE_BUILTIN_NAMES) | {"np", "pd"}

_ALLOWED_NODES = (
    ast.Module,
    ast.Expr,
    ast.Assign,
    ast.AugAssign,
    ast.If,
    ast.For,
    ast.Break,
    ast.Continue,
    ast.Pass,
    ast.Import,
    ast.ImportFrom,
    ast.alias,
    ast.Name,
    ast.Attribute,
    ast.Subscript,
    ast.Slice,
    ast.Constant,
    ast.JoinedStr,
    ast.FormattedValue,
    ast.List,
    ast.Tuple,
    ast.Dict,
    ast.Set,
    ast.Call,
    ast.keyword,
    ast.Starred,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.IfExp,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
    ast.comprehension,
    ast.Lambda,
    ast.arguments,
    ast.arg,
    ast.operator,
    ast.unaryop,
    ast.boolop,
    ast.cmpop,
    ast.Load,
    ast.Store,
)


def _is_blocked_name(name: str) -> bool:
    if name in _BLOCKED_NAMES:
        return True
    if name in _ALLOWED_TO_NAMES:
        return False
    return name.startswith(_BLOCKED_PREFIXES)


def _check_trendline_options(options: Any) -> None:
    """Plotly calls ``getattr(window, options["function"])``; allow known names only."""
    if options is None:
        return
    if not isinstance(options, dict):
        raise UnsafePlotlyCodeError("trendline_options must be a dict")
    function = options.get("function", "mean")
    if not isinstance(function, str) or function not in _TRENDLINE_FUNCTIONS:
        raise UnsafePlotlyCodeError(
            f"trendline function {function!r} is not allowed in generated Plotly code"
        )
    function_args = options.get("function_args", {})
    if not isinstance(function_args, dict) or any(
        callable(v) for v in function_args.values()
    ):
        raise UnsafePlotlyCodeError("trendline function_args must be plain values")


@functools.lru_cache(maxsize=None)
def _guard_trendline(func: Any) -> Any:
    """Wrap Plotly Express functions so trendline options are checked at runtime.

    The AST check only sees ``trendline_options=`` keywords; this also covers
    options passed positionally or built at runtime.
    """
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return func
    if "trendline_options" not in signature.parameters:
        return func

    @functools.wraps(func)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind_partial(*args, **kwargs)
        _check_trendline_options(bound.arguments.get("trendline_options"))
        return func(*args, **kwargs)

    return guarded


class _ModuleProxy:
    """Read-only view of a module without private names, I/O helpers or submodules."""

    __slots__ = ("_module", "_submodule_prefixes", "_guard_calls")

    def __init__(
        self,
        module: types.ModuleType,
        submodule_prefixes: tuple = (),
        guard_calls: bool = False,
    ):
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_submodule_prefixes", submodule_prefixes)
        object.__setattr__(self, "_guard_calls", guard_calls)

    def __getattr__(self, name: str) -> Any:
        if _is_blocked_name(name) or name in _HIDDEN_MODULE_NAMES:
            raise AttributeError(f"'{name}' is not available in generated Plotly code")
        value = getattr(self._module, name)
        if isinstance(value, types.ModuleType):
            if self._submodule_prefixes and value.__name__.startswith(
                self._submodule_prefixes
            ):
                return _ModuleProxy(value, self._submodule_prefixes)
            raise AttributeError(f"'{name}' is not available in generated Plotly code")
        if self._guard_calls and isinstance(value, types.FunctionType):
            return _guard_trendline(value)
        return value

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("modules are read-only in generated Plotly code")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("modules are read-only in generated Plotly code")

    def __repr__(self) -> str:
        return f"<restricted module {self._module.__name__}>"


_PX = _ModuleProxy(
    px,
    ("plotly.express.colors", "plotly.colors", "_plotly_utils.colors"),
    guard_calls=True,
)
_GO = _ModuleProxy(go, ("plotly.graph_objs",))
_SUBPLOTS = _ModuleProxy(plotly.subplots)
_PD = _ModuleProxy(pd)
_NP = _ModuleProxy(np)
_plotly_root = types.ModuleType("plotly")
_plotly_root.express = _PX
_plotly_root.graph_objects = _GO
_plotly_root.graph_objs = _GO
_plotly_root.subplots = _SUBPLOTS
_plotly_root.colors = _PX.colors
_PLOTLY = _ModuleProxy(_plotly_root)

_MODULE_ALIASES = frozenset({"px", "go", "pd", "np", "plotly"})

_IMPORTABLE = {
    "plotly": _PLOTLY,
    "plotly.express": _PX,
    "plotly.graph_objects": _GO,
    "plotly.graph_objs": _GO,
    "plotly.subplots": _SUBPLOTS,
    "pandas": _PD,
    "numpy": _NP,
}


def _restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level != 0 or name not in _IMPORTABLE:
        raise ImportError(f"Importing '{name}' is not allowed in generated Plotly code")
    if fromlist:
        return _IMPORTABLE[name]
    return _IMPORTABLE[name.partition(".")[0]]


def _is_plain_format_string(value: str) -> bool:
    """True if a str.format() template only uses positional or keyword fields.

    Fields such as ``{0.__class__}`` or ``{0[key]}`` traverse attributes and
    items, which would bypass the attribute checks.
    """
    try:
        parsed = list(string.Formatter().parse(value))
    except ValueError:
        return False
    for _, field_name, format_spec, _ in parsed:
        if field_name and not (field_name.isdigit() or field_name.isidentifier()):
            return False
        if format_spec and "{" in format_spec:
            if not _is_plain_format_string(format_spec):
                return False
    return True


def _reject(message: str) -> None:
    raise UnsafePlotlyCodeError(message)


def _check_binding(name: str, binds_module: bool = False) -> None:
    if name.startswith("__"):
        _reject(f"Name '{name}' is not allowed")
    if name in _PROTECTED_NAMES and not (binds_module and name in _MODULE_ALIASES):
        _reject(f"Assigning to '{name}' is not allowed")


def _check_attribute(node: ast.Attribute) -> None:
    attr = node.attr
    if attr in ("format", "format_map"):
        receiver = node.value
        if not (
            isinstance(receiver, ast.Constant)
            and isinstance(receiver.value, str)
            and _is_plain_format_string(receiver.value)
        ):
            _reject(f"'{attr}' is only allowed on literal templates with plain fields")
        return
    if _is_blocked_name(attr):
        _reject(f"Attribute '{attr}' is not allowed")
    if isinstance(node.ctx, ast.Store):
        # Only allow simple targets such as ``df.columns = [...]`` so library
        # classes and modules cannot be modified.
        if (
            attr not in _ASSIGNABLE_ATTRIBUTES
            or not isinstance(node.value, ast.Name)
            or node.value.id in _MODULE_ALIASES
        ):
            _reject(f"Assigning to attribute '{attr}' is not allowed")


def _check_import(node: ast.AST) -> None:
    if isinstance(node, ast.ImportFrom):
        if node.level or node.module not in _IMPORTABLE:
            _reject(f"Importing '{node.module}' is not allowed")
        for alias in node.names:
            if (
                alias.name == "*"
                or _is_blocked_name(alias.name)
                or alias.name in _HIDDEN_MODULE_NAMES
            ):
                _reject(f"Importing '{alias.name}' is not allowed")
            _check_binding(alias.asname or alias.name)
        return
    for alias in node.names:
        if alias.name not in _IMPORTABLE:
            _reject(f"Importing '{alias.name}' is not allowed")
        if alias.asname:
            # ``import numpy as np`` binds a module proxy, which is fine.
            _check_binding(alias.asname, binds_module=True)


def _check_dispatch_argument(node: ast.AST) -> None:
    """Arguments of apply/agg/transform must be literals, lambdas or known functions.

    Otherwise a string built at runtime (e.g. ``"to_" + "csv"``) could name a
    method that writes files.
    """
    if isinstance(node, ast.Lambda):
        return
    if isinstance(node, ast.Constant):
        # pandas falls back to ``getattr(numpy, name)`` for unknown names, so
        # the NumPy I/O helpers are blocked too.
        if isinstance(node.value, str) and (
            _is_blocked_name(node.value) or node.value in _HIDDEN_MODULE_NAMES
        ):
            _reject(f"'{node.value}' is not allowed as a function name")
        return
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        return
    if isinstance(node, ast.Name) and node.id in _SAFE_BUILTIN_NAMES:
        return
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in ("np", "pd")
    ):
        return
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for element in node.elts:
            _check_dispatch_argument(element)
        return
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if key is not None and not isinstance(key, ast.Constant):
                _reject(
                    "Dictionary keys passed to apply/agg/transform must be literals"
                )
            _check_dispatch_argument(value)
        return
    _reject(
        "Arguments to apply/agg/transform must be literals, lambdas, builtins or "
        "numpy/pandas functions"
    )


def _check_call(node: ast.Call) -> None:
    for keyword in node.keywords:
        # ``f(**options)`` would hide the keyword names from the checks below.
        if keyword.arg is None and not (
            isinstance(keyword.value, ast.Dict)
            and all(
                isinstance(key, ast.Constant) and isinstance(key.value, str)
                for key in keyword.value.keys
            )
        ):
            _reject("'**' is only allowed with dict literals that have string keys")

    if isinstance(node.func, ast.Attribute) and node.func.attr in _DISPATCH_METHODS:
        for argument in node.args:
            _check_dispatch_argument(argument)
        for keyword in node.keywords:
            _check_dispatch_argument(keyword.value)
        return
    for keyword in node.keywords:
        if keyword.arg in _DISPATCH_KEYWORDS:
            _check_dispatch_argument(keyword.value)
        elif keyword.arg is None:
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if key.value in _DISPATCH_KEYWORDS:
                    _check_dispatch_argument(value)


def validate_plotly_code(code: str) -> ast.Module:
    """Parse and validate generated Plotly code.

    Raises:
        UnsafePlotlyCodeError: If the code is not valid Python or uses a
            construct that is not allowed.
    """
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as e:
        raise UnsafePlotlyCodeError(f"Invalid Python syntax: {e}") from e

    # apply/agg/transform may only be called directly, so their arguments are
    # always checked: ``f = df.agg; f("to_csv", ...)`` would skip the check.
    call_targets = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            _reject(f"{type(node).__name__} is not allowed")
        if isinstance(node, ast.Name):
            if node.id.startswith("__"):
                _reject(f"Name '{node.id}' is not allowed")
            if isinstance(node.ctx, ast.Store):
                _check_binding(node.id)
        elif isinstance(node, ast.arg):
            _check_binding(node.arg)
        elif isinstance(node, ast.Attribute):
            _check_attribute(node)
            if node.attr in _DISPATCH_METHODS and id(node) not in call_targets:
                _reject(f"'{node.attr}' may only be called directly")
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str) and node.value.startswith("__"):
                _reject("String literals starting with '__' are not allowed")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            _check_import(node)
        elif isinstance(node, ast.Call):
            _check_call(node)
    return tree


def run_plotly_code(code: str, df: pd.DataFrame) -> Optional[Any]:
    """Validate and run generated Plotly code, returning the ``fig`` it defines.

    Raises:
        UnsafePlotlyCodeError: If the code fails validation.
        Exception: Any error raised while running the code.
    """
    tree = validate_plotly_code(code)

    safe_builtins: Dict[str, Any] = {
        name: getattr(builtins, name) for name in _SAFE_BUILTIN_NAMES
    }
    safe_builtins["__import__"] = _restricted_import

    namespace: Dict[str, Any] = {
        "__builtins__": safe_builtins,
        "df": df,
        "px": _PX,
        "go": _GO,
        "pd": _PD,
        "plotly": _PLOTLY,
    }
    exec(compile(tree, "<plotly_code>", "exec"), namespace)
    return namespace.get("fig")
