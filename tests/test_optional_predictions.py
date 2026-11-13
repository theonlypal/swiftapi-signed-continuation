import re
import pytest
from prediction_fixtures import prediction_bytes
from swiftapi_native_service import predictions as P
from swiftapi_native_service.experiment import MODEL


def parse(raw):
    return P.parse_predictions(raw, MODEL)


@pytest.mark.parametrize('name', P.FIELDS)
def test_optional_line_absence_equals_blank(name):
    raw = prediction_bytes()
    absent = re.sub(rb'^' + name.encode() + rb': .*\n', b'', raw, flags=re.M)
    assert parse(absent) == parse(raw)
    assert all(name not in row for run in parse(absent).values() for row in run.values())


def test_all_optional_lines_can_be_absent():
    assert parse(prediction_bytes(optional=False)) == parse(prediction_bytes())


def test_complete_classes_without_optional_lines():
    raw = prediction_bytes(optional=False)
    for _, _, arms, total in P.RUNS:
        for arm in arms:
            old = f'`[{arm}] [{MODEL}] [__/{total}] [{P.BLANK}]`'.encode()
            new = f'`[{arm}] [{MODEL}] [{total}/{total}] [R]`'.encode()
            raw = raw.replace(old, new)
    parsed = parse(raw)
    for run, _, arms, total in P.RUNS:
        for arm in arms:
            assert parsed[run][arm] == {'class_counts': {'R': total}}
    result = P.score(parsed['PRIMARY'], {arm: 1 for arm in P.PRIMARY_ARMS},
                     {arm: [{'class': 'R'}] for arm in P.PRIMARY_ARMS})
    for row in result['arms'].values():
        assert all(row['components'][name] == P.NOT_PREDICTED for name in P.FIELDS)


@pytest.mark.parametrize('name,value,expected', [
    ('first_token', '0', 0), ('output_bytes', '3', 3),
    ('generation_complete', 'true', True), ('generation_complete', 'false', False),
])
def test_present_optional_line_preserves_value(name, value, expected):
    raw = prediction_bytes(optional=False).replace(
        b'Arm VALID: Synthetic request input.\n',
        f'Arm VALID: Synthetic request input.\n\n{name}: {value}\n'.encode(), 1)
    assert parse(raw)['PRIMARY']['VALID'][name] == expected


@pytest.mark.parametrize('line', ['first_token: ', 'first_token: -1', 'first_token: 01',
    'output_bytes: 1.0', 'generation_complete: True', 'generation_complete: yes',
    'output_bytes: 1\noutput_bytes: 2'])
def test_present_optional_line_retains_strict_grammar(line):
    raw = prediction_bytes(optional=False).replace(b'Arm VALID: Synthetic request input.\n',
        ('Arm VALID: Synthetic request input.\n\n' + line + '\n').encode(), 1)
    with pytest.raises(P.PredictionFormatError):
        parse(raw)


def test_missing_optional_fields_do_not_hide_malformed_result():
    raw = prediction_bytes(optional=False).replace(b'[__/1]', b'[2/1]', 1)
    with pytest.raises(P.PredictionFormatError):
        parse(raw)
