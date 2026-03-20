"""Tests for pyntrace.providers — all providers mocked, no real API calls."""
from __future__ import annotations

import os
import sys
import types
import json
from unittest.mock import MagicMock, patch, call

import pytest

from pyntrace import providers


# ── Helpers ───────────────────────────────────────────────────────────────────

MSGS = [{"role": "user", "content": "Hello"}]
SYS = "You are helpful."


def _reset_clients():
    providers._CLIENTS.clear()
    providers._OFFLINE = False


@pytest.fixture(autouse=True)
def clean_clients():
    _reset_clients()
    yield
    _reset_clients()


def _make_openai_response(text="ok", prompt_tokens=5, completion_tokens=2):
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = text
    mock_resp.usage.prompt_tokens = prompt_tokens
    mock_resp.usage.completion_tokens = completion_tokens
    return mock_resp


def _fake_openai_module(client_mock):
    """Return a fake openai module stub with OpenAI and AzureOpenAI."""
    mod = types.ModuleType("openai")
    mod.OpenAI = MagicMock(return_value=client_mock)
    mod.AzureOpenAI = MagicMock(return_value=client_mock)
    return mod


# ── call() routing ────────────────────────────────────────────────────────────

class TestCallRouting:
    def test_claude_routes_to_anthropic(self):
        with patch.object(providers, "_call_anthropic", return_value=("hi", 1, 2)) as m:
            result = providers.call("claude-3-5-sonnet-20241022", MSGS)
        m.assert_called_once()
        assert result == ("hi", 1, 2)

    def test_gemini_routes_to_google(self):
        with patch.object(providers, "_call_google", return_value=("hi", 3, 4)) as m:
            providers.call("gemini-1.5-flash", MSGS)
        m.assert_called_once()

    def test_gpt_routes_to_openai(self):
        with patch.object(providers, "_call_openai", return_value=("hi", 5, 6)) as m:
            providers.call("gpt-4o-mini", MSGS)
        m.assert_called_once()

    def test_azure_prefix(self):
        with patch.object(providers, "_call_azure", return_value=("hi", 1, 2)) as m:
            providers.call("azure:my-gpt4o-deployment", MSGS)
        m.assert_called_once_with("my-gpt4o-deployment", MSGS, "")

    def test_bedrock_prefix(self):
        with patch.object(providers, "_call_bedrock", return_value=("hi", 1, 2)) as m:
            providers.call("bedrock:anthropic.claude-3-5-sonnet-20241022-v2:0", MSGS)
        m.assert_called_once_with("anthropic.claude-3-5-sonnet-20241022-v2:0", MSGS, "")

    def test_groq_prefix(self):
        with patch.object(providers, "_call_groq", return_value=("hi", 1, 2)) as m:
            providers.call("groq:llama-3.1-70b-versatile", MSGS)
        m.assert_called_once_with("llama-3.1-70b-versatile", MSGS, "")

    def test_mistral_prefix(self):
        with patch.object(providers, "_call_mistral", return_value=("hi", 1, 2)) as m:
            providers.call("mistral:mistral-large-latest", MSGS)
        m.assert_called_once_with("mistral-large-latest", MSGS, "")

    def test_cohere_prefix(self):
        with patch.object(providers, "_call_cohere", return_value=("hi", 1, 2)) as m:
            providers.call("cohere:command-r-plus", MSGS)
        m.assert_called_once_with("command-r-plus", MSGS, "")

    def test_together_prefix(self):
        with patch.object(providers, "_call_together", return_value=("hi", 1, 2)) as m:
            providers.call("together:meta-llama/Llama-3-70b-chat-hf", MSGS)
        m.assert_called_once_with("meta-llama/Llama-3-70b-chat-hf", MSGS, "")

    def test_ollama_prefix(self):
        with patch.object(providers, "_call_ollama", return_value=("hi", 0, 0)) as m:
            providers.call("ollama:llama3", MSGS)
        m.assert_called_once_with("llama3", MSGS, "")

    def test_offline_mode_uses_ollama(self):
        providers._OFFLINE = True
        with patch.object(providers, "_call_ollama", return_value=("hi", 0, 0)) as m:
            providers.call("gpt-4o", MSGS)
        m.assert_called_once()

    def test_call_llm_alias(self):
        """call_llm is a backward-compat alias for call."""
        with patch.object(providers, "_call_openai", return_value=("ok", 1, 1)):
            assert providers.call_llm("gpt-4o-mini", MSGS) == ("ok", 1, 1)


# ── Azure ─────────────────────────────────────────────────────────────────────

class TestAzure:
    def test_raises_without_env(self):
        env_backup = {k: os.environ.pop(k, None) for k in ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY")}
        try:
            mock_client = MagicMock()
            fake_openai = _fake_openai_module(mock_client)
            with patch.dict(sys.modules, {"openai": fake_openai}):
                with pytest.raises(EnvironmentError, match="AZURE_OPENAI_ENDPOINT"):
                    providers._call_azure("my-deploy", MSGS, "")
        finally:
            for k, v in env_backup.items():
                if v is not None:
                    os.environ[k] = v

    def test_calls_azure_client(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response("azure response", 10, 5)
        fake_openai = _fake_openai_module(mock_client)

        with patch.dict(sys.modules, {"openai": fake_openai}):
            with patch.dict(os.environ, {
                "AZURE_OPENAI_ENDPOINT": "https://test.openai.azure.com/",
                "AZURE_OPENAI_API_KEY": "test-key",
            }):
                text, inp, out = providers._call_azure("my-deploy", MSGS, SYS)

        assert text == "azure response"
        assert inp == 10
        assert out == 5

    def test_system_message_included(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response()
        fake_openai = _fake_openai_module(mock_client)

        with patch.dict(sys.modules, {"openai": fake_openai}):
            with patch.dict(os.environ, {
                "AZURE_OPENAI_ENDPOINT": "https://test.openai.azure.com/",
                "AZURE_OPENAI_API_KEY": "key",
            }):
                providers._call_azure("deploy", MSGS, SYS)

        call_args = mock_client.chat.completions.create.call_args
        messages_sent = call_args.kwargs.get("messages", call_args.args[1] if len(call_args.args) > 1 else [])
        assert any(m["role"] == "system" for m in messages_sent)


# ── Bedrock ───────────────────────────────────────────────────────────────────

class TestBedrock:
    def _make_boto_client(self, response_body: dict):
        mock_boto = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps(response_body).encode()
        mock_boto.invoke_model.return_value = {"body": mock_body}
        return mock_boto

    def test_anthropic_model_on_bedrock(self):
        mock_boto = self._make_boto_client({
            "content": [{"text": "bedrock reply"}],
            "usage": {"input_tokens": 8, "output_tokens": 3},
        })
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = MagicMock(return_value=mock_boto)

        with patch.dict(sys.modules, {"boto3": fake_boto3}):
            text, inp, out = providers._call_bedrock(
                "anthropic.claude-3-5-sonnet-20241022-v2:0", MSGS, SYS
            )

        assert text == "bedrock reply"
        assert inp == 8
        assert out == 3

    def test_converse_api_for_generic_model(self):
        mock_boto = MagicMock()
        mock_boto.converse.return_value = {
            "output": {"message": {"content": [{"text": "converse reply"}]}},
            "usage": {"inputTokens": 12, "outputTokens": 4},
        }
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = MagicMock(return_value=mock_boto)

        with patch.dict(sys.modules, {"boto3": fake_boto3}):
            text, inp, out = providers._call_bedrock("amazon.titan-text-express-v1", MSGS, "")

        assert text == "converse reply"
        assert inp == 12

    def test_llama_model_uses_prompt_format(self):
        mock_boto = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = json.dumps({
            "generation": "llama reply",
            "prompt_token_count": 20,
            "generation_token_count": 6,
        }).encode()
        mock_boto.invoke_model.return_value = {"body": mock_body}
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = MagicMock(return_value=mock_boto)

        with patch.dict(sys.modules, {"boto3": fake_boto3}):
            text, inp, out = providers._call_bedrock("meta.llama3-8b-instruct-v1:0", MSGS, "")

        assert text == "llama reply"
        assert inp == 20

    def test_missing_boto3_raises(self):
        with patch.dict(sys.modules, {"boto3": None}):  # type: ignore[dict-item]
            with pytest.raises((ImportError, SystemError)):
                providers._call_bedrock("some-model", MSGS, "")


# ── Groq ──────────────────────────────────────────────────────────────────────

class TestGroq:
    def test_raises_without_key(self):
        env_backup = os.environ.pop("GROQ_API_KEY", None)
        try:
            mock_client = MagicMock()
            fake_openai = _fake_openai_module(mock_client)
            with patch.dict(sys.modules, {"openai": fake_openai}):
                with pytest.raises(EnvironmentError, match="GROQ_API_KEY"):
                    providers._call_groq("llama-3-70b", MSGS, "")
        finally:
            if env_backup is not None:
                os.environ["GROQ_API_KEY"] = env_backup

    def test_calls_with_groq_base_url(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response("groq response", 7, 3)

        captured_kwargs = {}

        def capture_openai(**kwargs):
            captured_kwargs.update(kwargs)
            return mock_client

        fake_openai = types.ModuleType("openai")
        fake_openai.OpenAI = capture_openai

        with patch.dict(sys.modules, {"openai": fake_openai}):
            with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}):
                text, inp, out = providers._call_groq("llama-3.1-70b-versatile", MSGS, "")

        assert "groq.com" in captured_kwargs.get("base_url", "")
        assert text == "groq response"
        assert inp == 7


# ── Mistral ───────────────────────────────────────────────────────────────────

class TestMistral:
    def test_raises_without_key(self):
        env_backup = os.environ.pop("MISTRAL_API_KEY", None)
        try:
            with patch.dict(sys.modules, {"mistralai": None}):  # type: ignore[dict-item]
                fake_openai = types.ModuleType("openai")
                fake_openai.OpenAI = MagicMock()
                with patch.dict(sys.modules, {"openai": fake_openai}):
                    with pytest.raises(EnvironmentError, match="MISTRAL_API_KEY"):
                        providers._call_mistral("mistral-large-latest", MSGS, "")
        finally:
            if env_backup is not None:
                os.environ["MISTRAL_API_KEY"] = env_backup

    def test_native_sdk_when_available(self):
        mock_mistral_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "mistral native"
        mock_resp.usage.prompt_tokens = 6
        mock_resp.usage.completion_tokens = 2
        mock_mistral_client.chat.complete.return_value = mock_resp

        fake_mistralai = types.ModuleType("mistralai")
        fake_mistralai.Mistral = MagicMock(return_value=mock_mistral_client)

        with patch.dict(sys.modules, {"mistralai": fake_mistralai}):
            with patch.dict(os.environ, {"MISTRAL_API_KEY": "test-key"}):
                text, inp, out = providers._call_mistral("mistral-large-latest", MSGS, SYS)

        assert text == "mistral native"
        assert inp == 6

    def test_openai_compat_fallback(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response("mistral compat", 5, 2)

        captured_kwargs = {}

        def capture(**kwargs):
            captured_kwargs.update(kwargs)
            return mock_client

        fake_openai = types.ModuleType("openai")
        fake_openai.OpenAI = capture

        with patch.dict(sys.modules, {"mistralai": None, "openai": fake_openai}):  # type: ignore[dict-item]
            with patch.dict(os.environ, {"MISTRAL_API_KEY": "test-key"}):
                text, inp, out = providers._call_mistral("mistral-large-latest", MSGS, "")

        assert "mistral.ai" in captured_kwargs.get("base_url", "")
        assert text == "mistral compat"


# ── Cohere ────────────────────────────────────────────────────────────────────

class TestCohere:
    def test_raises_without_key(self):
        env_backup = os.environ.pop("COHERE_API_KEY", None)
        try:
            fake_cohere = types.ModuleType("cohere")
            fake_cohere.ClientV2 = MagicMock()
            with patch.dict(sys.modules, {"cohere": fake_cohere}):
                with pytest.raises(EnvironmentError, match="COHERE_API_KEY"):
                    providers._call_cohere("command-r-plus", MSGS, "")
        finally:
            if env_backup is not None:
                os.environ["COHERE_API_KEY"] = env_backup

    def test_calls_cohere_client(self):
        mock_client = MagicMock()
        mock_content = MagicMock()
        mock_content.text = "cohere response"
        mock_resp = MagicMock()
        mock_resp.message.content = [mock_content]
        mock_resp.usage.billed_units.input_tokens = 9
        mock_resp.usage.billed_units.output_tokens = 4
        mock_client.chat.return_value = mock_resp

        fake_cohere = types.ModuleType("cohere")
        fake_cohere.ClientV2 = MagicMock(return_value=mock_client)

        with patch.dict(sys.modules, {"cohere": fake_cohere}):
            with patch.dict(os.environ, {"COHERE_API_KEY": "test-key"}):
                text, inp, out = providers._call_cohere("command-r-plus", MSGS, SYS)

        assert text == "cohere response"
        assert inp == 9
        assert out == 4


# ── Together AI ───────────────────────────────────────────────────────────────

class TestTogether:
    def test_raises_without_key(self):
        env_backup = os.environ.pop("TOGETHER_API_KEY", None)
        try:
            mock_client = MagicMock()
            fake_openai = _fake_openai_module(mock_client)
            with patch.dict(sys.modules, {"openai": fake_openai}):
                with pytest.raises(EnvironmentError, match="TOGETHER_API_KEY"):
                    providers._call_together("meta-llama/Llama-3-70b", MSGS, "")
        finally:
            if env_backup is not None:
                os.environ["TOGETHER_API_KEY"] = env_backup

    def test_uses_together_base_url(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_openai_response("together response", 5, 2)

        captured_kwargs = {}

        def capture(**kwargs):
            captured_kwargs.update(kwargs)
            return mock_client

        fake_openai = types.ModuleType("openai")
        fake_openai.OpenAI = capture

        with patch.dict(sys.modules, {"openai": fake_openai}):
            with patch.dict(os.environ, {"TOGETHER_API_KEY": "tok_test"}):
                text, inp, out = providers._call_together("meta-llama/Llama-3-70b", MSGS, "")

        assert "together.xyz" in captured_kwargs.get("base_url", "")
        assert text == "together response"


# ── configure / get_judge_model ───────────────────────────────────────────────

class TestConfigure:
    def test_offline_sets_local_judge(self):
        providers.configure(offline=True, local_judge_model="mistral")
        assert providers.get_judge_model() == "mistral"
        providers.configure(offline=False)

    def test_online_uses_default_judge(self):
        providers.configure(offline=False, judge_model="claude-3-5-haiku-20241022")
        assert providers.get_judge_model() == "claude-3-5-haiku-20241022"
        providers.configure(judge_model="gpt-4o-mini")

    def test_offline_routes_to_ollama_not_real_provider(self):
        providers._OFFLINE = True
        with patch.object(providers, "_call_ollama", return_value=("hi", 0, 0)) as m:
            with patch.object(providers, "_call_openai") as openai_mock:
                providers.call("gpt-4o", MSGS)
        m.assert_called_once()
        openai_mock.assert_not_called()
