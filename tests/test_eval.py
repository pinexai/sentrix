"""Tests for sentrix.eval — dataset, scorers, experiment."""
import pytest


class TestDataset:
    def test_create_and_add(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        ds = Dataset("test-ds", db_path=tmp_db)
        item = ds.add(input="hello", expected_output="world", metadata={"tag": "test"})
        assert len(ds) == 1
        assert item.input == "hello"
        assert item.expected_output == "world"

    def test_iteration(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        ds = Dataset("iter-test", db_path=tmp_db)
        ds.add(input="q1", expected_output="a1")
        ds.add(input="q2", expected_output="a2")
        items = list(ds)
        assert len(items) == 2
        assert items[0].input == "q1"
        assert items[1].input == "q2"

    def test_from_list(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        items = [
            {"input": "What is 2+2?", "expected_output": "4"},
            {"input": "What is the capital of France?", "expected_output": "Paris"},
        ]
        ds = Dataset.from_list("qa-test", items)
        assert len(ds) == 2

    def test_to_list(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        ds = Dataset("to-list-test", db_path=tmp_db)
        ds.add(input="hello", expected_output="world")
        result = ds.to_list()
        assert isinstance(result, list)
        assert result[0]["input"] == "hello"


class TestScorers:
    def test_exact_match_pass(self):
        from sentrix.eval.scorers import exact_match
        assert exact_match("hello", "hello") == 1.0

    def test_exact_match_fail(self):
        from sentrix.eval.scorers import exact_match
        assert exact_match("hello", "world") == 0.0

    def test_contains(self):
        from sentrix.eval.scorers import contains
        assert contains("The answer is 42", "42") == 1.0
        assert contains("The answer is 42", "99") == 0.0

    def test_levenshtein_sim_identical(self):
        from sentrix.eval.scorers import levenshtein_sim
        assert levenshtein_sim("hello", "hello") == pytest.approx(1.0)

    def test_levenshtein_sim_different(self):
        from sentrix.eval.scorers import levenshtein_sim
        score = levenshtein_sim("abc", "xyz")
        assert 0.0 <= score < 1.0

    def test_regex_match(self):
        from sentrix.eval.scorers import regex_match
        scorer = regex_match(r"\d{4}")
        assert scorer("The year is 2024", "") == 1.0
        assert scorer("No numbers here", "") == 0.0

    def test_no_pii_clean(self):
        from sentrix.eval.scorers import no_pii
        assert no_pii("The weather is nice today.") == 1.0

    def test_no_pii_detects_email(self):
        from sentrix.eval.scorers import no_pii
        assert no_pii("Contact us at user@example.com") == 0.0

    def test_no_pii_detects_ssn(self):
        from sentrix.eval.scorers import no_pii
        assert no_pii("SSN: 123-45-6789") == 0.0

    def test_json_schema_valid(self):
        from sentrix.eval.scorers import json_schema_valid
        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        try:
            scorer = json_schema_valid(schema)
            assert scorer('{"name": "Alice"}') == 1.0
            assert scorer('{"name": 123}') == 0.0
            assert scorer("not json") == 0.0
        except ImportError:
            pytest.skip("jsonschema not installed")


class TestExperiment:
    def test_experiment_run(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        from sentrix.eval.experiment import Experiment
        from sentrix.eval.scorers import exact_match

        ds = Dataset("exp-test", db_path=tmp_db)
        ds.add(input="2+2", expected_output="4")
        ds.add(input="3+3", expected_output="6")

        exp = Experiment("math-test", ds, lambda x: x.replace("+", "+").replace("2+2", "4").replace("3+3", "6"), scorers=[exact_match], db_path=tmp_db)
        results = exp.run()

        assert len(results.results) == 2
        assert results.pass_rate == 1.0

    def test_experiment_handles_errors(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        from sentrix.eval.experiment import Experiment

        ds = Dataset("error-test", db_path=tmp_db)
        ds.add(input="test", expected_output="ok")

        def _broken(x):
            raise ValueError("Intentional error")

        exp = Experiment("error-exp", ds, _broken, db_path=tmp_db)
        results = exp.run()

        assert len(results.results) == 1
        assert results.results[0].error is not None

    def test_experiment_to_json(self, tmp_db):
        from sentrix.eval.dataset import Dataset
        from sentrix.eval.experiment import Experiment

        ds = Dataset("json-test", db_path=tmp_db)
        ds.add(input="hi", expected_output="hello")

        exp = Experiment("json-exp", ds, lambda x: "hello", db_path=tmp_db)
        results = exp.run()
        d = results.to_json()

        assert "experiment_name" in d
        assert "pass_rate" in d
        assert "results" in d
