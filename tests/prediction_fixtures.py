from swiftapi_native_service.predictions import RUNS, FIELDS, BLANK, FORBIDDEN_FIELDS
from swiftapi_native_service.experiment import MODEL


def prediction_bytes(optional=True):
    lines = ['# Synthetic test input', '']
    for run, heading, arms, total in RUNS:
        lines += [heading, '']
        for arm in arms:
            lines += [f'### {arm}', '', f'Arm {arm}: Synthetic request input.', '',
                      f'`[{arm}] [{MODEL}] [__/{total}] [{BLANK}]`', '']
            if optional:
                for field in FIELDS:
                    if field not in FORBIDDEN_FIELDS.get((run, arm), ()):
                        lines += [f'{field}: {BLANK}', '']
            lines += [f'`python -m swiftapi_native_service.experiment question --config RUN_CONFIG_{run}.json --out {run}_OUTPUT --arm {arm}`', '']
    return '\n'.join(lines).encode()
