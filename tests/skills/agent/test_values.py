import argparse

import pytest

from quality.agent import score
from tests.skills.score.support import SCORE, module

SCRIPT = module(SCORE, "score_values_under_test")


def outcome(parse, text: str) -> float | str:
    try:
        return parse(text)
    except argparse.ArgumentTypeError as error:
        return str(error)


def test_the_script_and_quality_agent_share_the_value_markers():
    assert (SCRIPT.DASH, SCRIPT.NEW, SCRIPT.UNKNOWN) == (score.DASH, score.NEW, score.UNKNOWN)


@pytest.mark.parametrize("text", ["0", "55.5", "100", "-1", "101", "x"])
def test_the_script_and_quality_agent_parse_percentages_alike(text):
    assert outcome(SCRIPT.percent, text) == outcome(score.percent, text)
