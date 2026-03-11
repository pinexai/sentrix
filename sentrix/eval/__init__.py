"""sentrix.eval — Evaluation framework: datasets, scorers, experiments, model comparison."""
from sentrix.eval.dataset import Dataset, DatasetItem
from sentrix.eval.experiment import Experiment, ExperimentResults
from sentrix.eval import scorers
from sentrix.eval.compare import compare_models, prompt_ab_test

__all__ = [
    "Dataset",
    "DatasetItem",
    "Experiment",
    "ExperimentResults",
    "scorers",
    "compare_models",
    "prompt_ab_test",
]
