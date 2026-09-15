from campus_ops.workers.beaconing import periodicity_score


def test_periodicity_score_accepts_low_variation_intervals():
    result = periodicity_score([0, 10, 20, 30, 40, 50, 60, 70])
    assert result is not None
    median, cv = result
    assert median == 10
    assert cv == 0


def test_periodicity_score_rejects_too_few_samples_and_fast_noise():
    assert periodicity_score([0, 10, 20]) is None
    assert periodicity_score([0, 1, 2, 3, 4, 5, 6, 7]) is None
