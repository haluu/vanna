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
