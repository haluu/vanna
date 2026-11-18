"""
Regression tests for security fixes.

These tests use mocks only and need no external services.
"""

import sys
import types
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# CVE-2026-4229: SQL injection in legacy BigQuery_VectorStore
# ---------------------------------------------------------------------------


@pytest.fixture
def bigquery_vector_store(monkeypatch):
    pytest.importorskip("google.cloud.bigquery")

    # The module imports Vertex AI at import time; stub it so the test does not
    # need the Vertex AI SDK installed.
    vertexai = types.ModuleType("vertexai")
    language_models = types.ModuleType("vertexai.language_models")
    language_models.TextEmbeddingInput = MagicMock()
    language_models.TextEmbeddingModel = MagicMock()
    vertexai.language_models = language_models
    monkeypatch.setitem(sys.modules, "vertexai", vertexai)
    monkeypatch.setitem(sys.modules, "vertexai.language_models", language_models)
    monkeypatch.delitem(
        sys.modules, "vanna.legacy.google.bigquery_vector", raising=False
    )

    from vanna.legacy.google.bigquery_vector import BigQuery_VectorStore

    class Store(BigQuery_VectorStore):
        def system_message(self, message):
            return message

        def user_message(self, message):
            return message

        def assistant_message(self, message):
            return message

        def submit_prompt(self, prompt, **kwargs):
            return ""

    store = object.__new__(Store)
    store.conn = MagicMock()
    store.table_id = "project.dataset.training_data"
    store.generate_question_embedding = lambda question: [0.1, 0.2]
    return store


def _query_parameters(call):
    job_config = call.kwargs["job_config"]
    return {p.name: p.value for p in job_config.query_parameters}


def test_bigquery_remove_training_data_is_parameterized(bigquery_vector_store):
    payload = "x' OR '1'='1"

    assert bigquery_vector_store.remove_training_data(id=payload) is True

    call = bigquery_vector_store.conn.query.call_args
    sql = call.args[0]
    assert payload not in sql
    assert "@id" in sql
    assert _query_parameters(call) == {"id": payload}


def test_bigquery_fetch_similar_training_data_is_parameterized(bigquery_vector_store):
    payload = "sql' OR '1'='1"

    bigquery_vector_store.fetch_similar_training_data(
        training_data_type=payload, question="q", n_results=5
    )

    call = bigquery_vector_store.conn.query.call_args
    sql = call.args[0]
    assert payload not in sql
    assert "@training_data_type" in sql
    assert _query_parameters(call) == {"training_data_type": payload}


# ---------------------------------------------------------------------------
# CVE-2024-5565 / CVE-2024-5826 / #1062: RCE through LLM-generated Plotly code
# ---------------------------------------------------------------------------

pd = pytest.importorskip("pandas")
go = pytest.importorskip("plotly.graph_objects")

from vanna.legacy.base.plotly_sandbox import (  # noqa: E402
    UnsafePlotlyCodeError,
    run_plotly_code,
    validate_plotly_code,
)


@pytest.fixture
def sales_df():
    return pd.DataFrame(
        {
            "month": ["2024-01-01", "2024-02-01", "2024-03-01"],
            "region": ["north", "south", "north"],
            "sales": [10.5, 20.25, 30.0],
            "open": [1, 2, 3],
        }
    )


VALID_PLOTLY_SNIPPETS = [
    # Typical LLM output
    """
import plotly.express as px
fig = px.bar(df, x='region', y='sales', title='Sales by region')
fig.update_layout(xaxis_title='Region', yaxis_title='Sales')
""",
    """
import plotly.graph_objects as go
fig = go.Figure(go.Indicator(mode="number", value=df['sales'].sum(),
                             title={"text": "Total sales"}))
""",
    """
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
df['month'] = pd.to_datetime(df['month'])
df['log_sales'] = np.log(df['sales'])
fig = make_subplots(specs=[[{"secondary_y": True}]])
fig.add_trace(go.Bar(x=df['month'], y=df['sales'], name='Sales'), secondary_y=False)
fig.add_trace(go.Scatter(x=df['month'], y=df['log_sales'], name='Log'), secondary_y=True)
fig.update_layout(title=go.layout.Title(text="Sales"))
""",
    # Names that are pre-bound without imports, comprehensions using
    # top-level variables, string formatting and groupby aggregation
    """
grouped = df.groupby('region').agg(total=('sales', 'sum')).reset_index()
grouped.columns = ['region', 'total']
threshold = 15
labels = [f"{r}: {t:.1f}" for r, t in zip(grouped['region'], grouped['total']) if t > threshold]
grouped['label'] = grouped['total'].apply(lambda v: "{:.2f}".format(v))
for _, row in grouped.iterrows():
    print(row['label'])
fig = px.pie(grouped, names='region', values='total',
             color_discrete_sequence=px.colors.qualitative.Plotly)
""",
    """
import plotly
fig = plotly.graph_objects.Figure(
    data=[plotly.graph_objects.Candlestick(x=df.month, open=df.open, high=df.sales,
                                           low=df.open, close=df.sales)]
)
""",
]


@pytest.mark.parametrize("code", VALID_PLOTLY_SNIPPETS)
def test_plotly_sandbox_runs_typical_chart_code(code, sales_df):
    fig = run_plotly_code(code, sales_df)
    assert isinstance(fig, go.Figure)


MALICIOUS_PLOTLY_SNIPPETS = [
    # PoC from vanna-ai/vanna#1062
    "__import__('os').system('echo pwned > {marker}')",
    "import os\nos.system('echo pwned > {marker}')",
    "import subprocess\nsubprocess.run(['touch', '{marker}'])",
    "from os import system\nsystem('touch {marker}')",
    "import plotly.io as pio\npio.write_html(go.Figure(), '{marker}')",
    "fig = px.data.os.system('touch {marker}')",
    "fig = px.np.save('{marker}', [1])",
    "fig = ().__class__.__base__.__subclasses__()",
    "open('{marker}', 'w').write('pwned')",
    "eval(\"open('{marker}', 'w')\")",
    "getattr(df, 'to_csv')('{marker}')",
    "df.to_csv('{marker}')",
    "df.to_pickle('{marker}')",
    "pd.read_csv('{marker}')",
    "pd.DataFrame({{'a': [1]}}).to_csv('{marker}')",
    "px.bar(df).write_html('{marker}')",
    "df.apply('to_csv', path_or_buf='{marker}')",
    "name = 'to_' + 'csv'\ndf.apply(name, path_or_buf='{marker}')",
    "s = pd.Series(name='to_csv')\ndf.apply(s.name, path_or_buf='{marker}')",
    "len = 'to_csv'\ndf.apply(len, path_or_buf='{marker}')",
    "f = lambda len: df.apply(len, path_or_buf='{marker}')\nf('to_csv')",
    "np = df\ndf.apply(np.to_csv, path_or_buf='{marker}')",
    "fig = '{{0.__globals__}}'.format(px.bar)",
    "fig = str.format('{{0.__class__}}', 1)",
    "g = (x for x in [1])\nfig = g.gi_frame.f_back",
    "df.query('sales > 1')",
    "pd.eval('1 + 1')",
    "pd.options.plotting.backend = 'os'",
    "pd.DataFrame.sum = lambda self: 0",
    "import numpy as np\nnp.save('{marker}', [1])",
    "options = pd.options",
    "def f():\n    pass",
    "class A:\n    pass",
    "while True:\n    pass",
    "try:\n    pass\nexcept Exception:\n    pass",
    "with open('{marker}') as f:\n    pass",
    "x = '__class__'",
]


@pytest.mark.parametrize("template", MALICIOUS_PLOTLY_SNIPPETS)
def test_plotly_sandbox_blocks_code_execution(template, sales_df, tmp_path):
    marker = tmp_path / "pwned"
    code = template.format(marker=marker.as_posix())

    # Rejected by validation, or the name is missing from the restricted
    # builtins / module proxies.
    with pytest.raises((UnsafePlotlyCodeError, AttributeError, NameError)):
        run_plotly_code(code, sales_df)

    assert not marker.exists()


def test_plotly_sandbox_rejects_before_running():
    with pytest.raises(UnsafePlotlyCodeError):
        validate_plotly_code("import os")


def test_get_plotly_figure_falls_back_on_malicious_code(sales_df, tmp_path):
    from vanna.legacy.base import VannaBase

    marker = tmp_path / "pwned"
    vn = MagicMock()

    fig = VannaBase.get_plotly_figure(
        vn,
        plotly_code=f"__import__('os').system('echo pwned > {marker.as_posix()}')",
        df=sales_df,
    )

    assert isinstance(fig, go.Figure)
    assert not marker.exists()
    vn.log.assert_called_once()


# ---------------------------------------------------------------------------
# Legacy Flask app: Werkzeug debugger and unauthenticated log websocket
# ---------------------------------------------------------------------------


@pytest.fixture
def legacy_flask_api():
    pytest.importorskip("flasgger")
    pytest.importorskip("flask_sock")
    from vanna.legacy.flask import VannaFlaskAPI
    from vanna.legacy.flask.auth import NoAuth

    class DenyAllAuth(NoAuth):
        def is_logged_in(self, user):
            return False

    def make(auth=None):
        return VannaFlaskAPI(vn=MagicMock(), auth=auth or NoAuth(), debug=True)

    make.DenyAllAuth = DenyAllAuth
    return make


def test_legacy_flask_run_never_enables_werkzeug_debugger(legacy_flask_api):
    app = legacy_flask_api()
    app.flask_app.run = MagicMock()

    app.run()

    assert app.flask_app.run.call_args.kwargs["debug"] is False


def _connect_log_socket(app):
    import threading

    from simple_websocket import Client
    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", 0, app.flask_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = Client.connect(f"ws://127.0.0.1:{server.server_port}/api/v0/log")
        try:
            # Give the handler time to run its auth check.
            client.receive(timeout=1)
        except Exception:
            pass
        connected = client.connected
        if connected:
            client.close()
        return connected
    finally:
        server.shutdown()


def test_legacy_flask_log_socket_requires_auth(legacy_flask_api):
    app = legacy_flask_api(auth=legacy_flask_api.DenyAllAuth())

    assert _connect_log_socket(app) is False
    assert app.ws_clients == []


def test_legacy_flask_log_socket_allows_logged_in_users(legacy_flask_api):
    app = legacy_flask_api()

    assert _connect_log_socket(app) is True


# ---------------------------------------------------------------------------
# FileSystemConversationStore: path traversal and conversation takeover
# ---------------------------------------------------------------------------


@pytest.fixture
def conversation_store(tmp_path):
    from vanna.integrations.local import FileSystemConversationStore

    return FileSystemConversationStore(base_dir=str(tmp_path / "conversations"))


def _user(user_id):
    from vanna.core.user import User

    return User(id=user_id, email=f"{user_id}@example.com", group_memberships=[])


@pytest.mark.parametrize(
    "conversation_id",
    [
        "..",
        ".",
        "",
        "../escaped",
        "a/../../escaped",
        "..\\escaped",
        "{absolute}",
        "C:escaped",
        "a\0b",
    ],
)
async def test_conversation_store_rejects_path_traversal(
    conversation_store, tmp_path, conversation_id
):
    from vanna.core.storage import Conversation, Message

    conversation_id = conversation_id.replace(
        "{absolute}", (tmp_path / "escaped").as_posix()
    )

    conversation = Conversation(
        id=conversation_id,
        user=_user("alice"),
        messages=[Message(role="user", content="hi")],
    )

    with pytest.raises(ValueError):
        await conversation_store.update_conversation(conversation)
    with pytest.raises(ValueError):
        await conversation_store.get_conversation(conversation_id, _user("alice"))

    assert not (tmp_path / "escaped").exists()
    assert not (tmp_path / "metadata.json").exists()


async def test_conversation_store_accepts_normal_ids(conversation_store):
    import uuid

    from vanna.core.storage import Conversation, Message

    for conversation_id in (str(uuid.uuid4()), "conv_123", "my.conversation"):
        conversation = Conversation(
            id=conversation_id,
            user=_user("alice"),
            messages=[Message(role="user", content="hi")],
        )
        await conversation_store.update_conversation(conversation)
        loaded = await conversation_store.get_conversation(
            conversation_id, _user("alice")
        )
        assert loaded is not None
        assert [m.content for m in loaded.messages] == ["hi"]


async def test_conversation_store_prevents_takeover(conversation_store):
    from vanna.core.storage import Conversation, Message

    await conversation_store.create_conversation("shared", _user("alice"), "secret")

    # Bob reuses Alice's conversation ID; the agent treats it as a new
    # conversation because get_conversation() returns None for Bob.
    assert await conversation_store.get_conversation("shared", _user("bob")) is None
    hijack = Conversation(
        id="shared", user=_user("bob"), messages=[Message(role="user", content="x")]
    )
    with pytest.raises(PermissionError):
        await conversation_store.update_conversation(hijack)

    assert await conversation_store.get_conversation("shared", _user("bob")) is None
    alice_view = await conversation_store.get_conversation("shared", _user("alice"))
    assert [m.content for m in alice_view.messages] == ["secret"]
