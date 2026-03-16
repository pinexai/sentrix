"""pyntrace.eval — Evaluation framework: datasets, scorers, experiments, model comparison."""
from pyntrace.eval.dataset import Dataset, DatasetItem
from pyntrace.eval.experiment import Experiment, ExperimentResults
from pyntrace.eval import scorers
from pyntrace.eval.compare import compare_models, prompt_ab_test

__all__ = [
    "Dataset",
    "DatasetItem",
    "Experiment",
    "ExperimentResults",
    "scorers",
    "compare_models",
    "prompt_ab_test",
]
