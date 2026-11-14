import pytest

from tests.bench import support


def test_busy_share_counts_iowait_as_idle(tmp_path, monkeypatch):
    stat = tmp_path / "stat"
    samples = iter(["cpu  400 0 100 1000 200 0 0 0 0 0\ncpu0 1 1 1 1 1 0 0 0 0 0\n"])
    stat.write_text("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 1 1 1 1 0 0 0 0 0\n")
    monkeypatch.setattr(support, "STAT", stat)
    monkeypatch.setattr(support.time, "sleep", lambda _seconds: stat.write_text(next(samples)))
    assert support.cpu_busy(1) == pytest.approx(100 * 300 / 700)


def test_busy_host_skips_the_timing(monkeypatch):
    monkeypatch.setattr(support, "cpu_busy", lambda _seconds: support.QUIET_PERCENT)
    with pytest.raises(pytest.skip.Exception, match="50 % busy after"):
        support.require_quiet_host("after")


def test_quiet_host_lets_the_timing_count(monkeypatch):
    monkeypatch.setattr(support, "cpu_busy", lambda _seconds: support.QUIET_PERCENT - 0.1)
    support.require_quiet_host("before")
