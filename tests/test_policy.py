import copy
import json

import pytest

from sf_smartwatch.calibrate import calibrated_policy, thresholds
from sf_smartwatch.policy import DEFAULT_POLICY, Policy, PolicyError, validate


def test_default_is_valid_and_load_roundtrips(tmp_path):
    p = tmp_path / 'p.json'
    p.write_text(json.dumps(DEFAULT_POLICY))
    assert Policy.load(str(p)).doc == DEFAULT_POLICY


def test_not_json_is_a_policy_error(tmp_path):
    p = tmp_path / 'p.json'
    p.write_text('{nope')
    with pytest.raises(PolicyError) as e:
        Policy.load(str(p))
    assert e.value.code == 'WATCH-BAD-POLICY'


@pytest.mark.parametrize('path,value', [(('reset', 'level'), ['critical']), (('reset', 'mode'), {}), (('schema',), 1),
                                        (('reset', 'on_timeout'), None), (('levels',), {}), (('limits',), [])])
def test_wrong_types_are_policy_errors(path, value):
    d = copy.deepcopy(DEFAULT_POLICY)
    t = d
    for k in path[:-1]:
        t = t[k]
    t[path[-1]] = value
    with pytest.raises(PolicyError):
        validate(d)


def test_calibration_profiles_and_names():
    ds = list(range(1, 1001))
    doc = calibrated_policy(DEFAULT_POLICY, ds, 'staging', [900, 950, 990])
    assert [x['min_density_micro'] for x in doc['levels']] == [900, 950, 990]
    assert doc['environment'] == 'staging'
    doc = calibrated_policy(DEFAULT_POLICY, ds, 'prod', [500, 900], ['warm', 'hot'])
    assert doc['reset']['level'] == 'hot'


@pytest.mark.parametrize('bad', [[], [1.5], [True], ['5'], [-1]])
def test_calibration_refuses_bad_input(bad):
    with pytest.raises(ValueError):
        thresholds(bad, [950])
