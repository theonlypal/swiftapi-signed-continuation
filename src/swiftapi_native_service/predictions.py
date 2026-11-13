
import re

CLASSES = ('V0', 'V1', 'V2', 'VU', 'NV', 'R', 'RF', 'SB', 'TC', 'operational')
PRIMARY_ARMS = ('VALID', 'SIGNED_DENIAL', 'MISSING_GRANT', 'INVALID_SIGNATURE', 'EXPIRED', 'REUSED',
                'WRONG_SCOPE', 'WRONG_REQUEST', 'UNKNOWN_KEY', 'MALFORMED_KEY', 'REVOKED')
SECONDARY_ARMS = ('VALID', 'MISSING_GRANT')
RUNS = (('PRIMARY', '## Run 1: PRIMARY WITNESS_ONE', PRIMARY_ARMS, 1),
        ('SECONDARY', '## Run 2: SECONDARY BANK_188', SECONDARY_ARMS, 188))
FIELDS = ('first_token', 'output_bytes', 'generation_complete')
BLANK = '____'
NOT_PREDICTED, MATCH, MISMATCH, INCOMPLETE = 'NOT_PREDICTED', 'MATCH', 'MISMATCH', 'INCOMPLETE'

FORBIDDEN_FIELDS = {('SECONDARY', 'VALID'): ('first_token',)}

_INTEGER = re.compile(r'(?:0|[1-9][0-9]*)\Z')
_COMMAND = re.compile(r'`python -m swiftapi_native_service\.experiment question --config \S+ --out \S+ --arm (\w+)`\Z')


class PredictionFormatError(ValueError):
    pass


def _refuse(condition, message):
    if not condition:
        raise PredictionFormatError(message)


def _section(run, arm, lines, model, total):
    pass
    where = f'{run} {arm}'
    result = re.compile(r'`\[' + re.escape(arm) + r'\] \[' + re.escape(model) + r'\] \[(__|[0-9]+)/' + str(total)
                        + r'\] \[(____|[A-Za-z0-9]+)\]`\Z')
    results, fields, seen = [], {}, {'question': 0, 'label': 0, 'command': 0}
    for line in lines:
        if not line.strip():
            continue
        _refuse(line == line.strip(), f'{where}: line has leading or trailing whitespace')
        if line.startswith(f'Arm {arm}: '):
            seen['question'] += 1
        elif line == 'My prediction:':
            seen['label'] += 1
        elif line.startswith('`['):
            match = result.match(line)
            _refuse(match is not None, f'{where}: malformed result line')
            results.append(match.groups())
        elif line.startswith('`python '):
            match = _COMMAND.match(line)
            _refuse(match is not None and match.group(1) == arm, f'{where}: malformed command line')
            seen['command'] += 1
        elif line.split(':', 1)[0] in FIELDS:
            name, _, value = line.partition(': ')
            _refuse(line == f'{name}: {value}' and value != '', f'{where}: malformed {name} line')
            _refuse(name not in fields, f'{where}: {name} appears more than once')
            fields[name] = value
        else:
            raise PredictionFormatError(f'{where}: line is not part of the template')
    _refuse(seen['question'] == 1 and seen['command'] == 1 and seen['label'] <= 1,
            f'{where}: question, label or command line missing or repeated')
    forbidden = FORBIDDEN_FIELDS.get((run, arm), ())
    entry = {}
    
    
    _refuse(results, f'{where}: result line is missing')
    if len(results) == 1:
        count, cls = results[0]
        if cls == BLANK:
            _refuse(count == '__', f'{where}: a count without a class')
        else:
            _refuse(cls in CLASSES, f'{where}: unknown class')
            _refuse(count == '__' or (_INTEGER.match(count) and int(count) == total),
                    f'{where}: a single class must cover all {total}')
            entry['class_counts'] = {cls: total}
    else:
        counts = {}
        for count, cls in results:
            _refuse(cls != BLANK and count != '__', f'{where}: a mixed prediction needs a class and a count on every line')
            _refuse(cls in CLASSES, f'{where}: unknown class')
            _refuse(_INTEGER.match(count) and int(count) >= 1, f'{where}: counts must be positive whole numbers')
            _refuse(cls not in counts, f'{where}: a class is listed twice')
            counts[cls] = int(count)
        _refuse(sum(counts.values()) == total, f'{where}: counts do not sum to {total}')
        entry['class_counts'] = counts
    for name in FIELDS:
        value = fields.get(name, BLANK)
        if value == BLANK:
            continue
        _refuse(name not in forbidden, f'{where}: {name} cannot be predicted for this arm')
        if name == 'generation_complete':
            _refuse(value in ('true', 'false'), f'{where}: generation_complete must be true or false')
            entry[name] = value == 'true'
        else:
            _refuse(_INTEGER.match(value) is not None, f'{where}: {name} must be a non-negative whole number')
            entry[name] = int(value)
    return entry


def parse_predictions(raw, model):
    pass
    _refuse(type(raw) is bytes and raw, 'Predictions file is empty')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise PredictionFormatError('Predictions file is not UTF-8') from None
    _refuse('\r' not in text, 'Predictions file has carriage returns')
    lines = text.split('\n')
    headings = [heading for _, heading, _, _ in RUNS]
    positions = [[i for i, line in enumerate(lines) if line == heading] for heading in headings]
    _refuse(all(len(found) == 1 for found in positions), 'Each run heading must appear exactly once')
    starts = [found[0] for found in positions]
    _refuse(starts == sorted(starts), 'Run headings are out of order')
    _refuse(not any(line.startswith('## Run ') and line not in headings for line in lines), 'Unknown run heading')
    parsed = {}
    for index, (run, _, arms, total) in enumerate(RUNS):
        body = lines[starts[index] + 1:starts[index + 1] if index + 1 < len(RUNS) else len(lines)]
        marks = [i for i, line in enumerate(body) if line.startswith('#')]
        names = [body[i] for i in marks]
        _refuse(names == ['### ' + arm for arm in arms], f'{run}: arm sections are missing, repeated or out of order')
        _refuse(not any(line.strip() for line in body[:marks[0]]), f'{run}: text before the first arm')
        parsed[run] = {}
        for position, arm in enumerate(arms):
            end = marks[position + 1] if position + 1 < len(marks) else len(body)
            parsed[run][arm] = _section(run, arm, body[marks[position] + 1:end], model, total)
    return parsed


def select_for_run(parsed, population, schedule):
    pass
    run = 'SECONDARY' if population == 'BANK_188' else 'PRIMARY'
    available = parsed[run]
    _refuse(all(arm in available for arm in schedule), f'{run}: a scheduled arm has no section in the sealed file')
    return run, {arm: available[arm] for arm in schedule}


REGISTERED_COMPARISON = 'REGISTERED_COMPARISON'
NOT_REGISTERED_COMPARISON = 'NOT_REGISTERED_COMPARISON'


def comparison_scope(config):
    pass
    purpose, mode, authority = config.get('purpose'), config.get('mode'), config.get('authority')
    registered = (purpose == 'PREREGISTERED_STUDY' and mode == 'FRESH_MODEL_EXECUTION'
                  and authority == 'LIVE_SWIFTAPI')
    differs = [name for name, value, wanted in (('purpose', purpose, 'PREREGISTERED_STUDY'),
                                                ('mode', mode, 'FRESH_MODEL_EXECUTION'),
                                                ('authority', authority, 'LIVE_SWIFTAPI')) if value != wanted]
    return {'kind': REGISTERED_COMPARISON if registered else NOT_REGISTERED_COMPARISON,
            'registered_comparison': registered,
            'purpose': purpose, 'mode': mode, 'authority': authority,
            'predicted_conditions': {'purpose': 'PREREGISTERED_STUDY', 'mode': 'FRESH_MODEL_EXECUTION',
                                     'authority': 'LIVE_SWIFTAPI'},
            'differs_in': differs,
            'meaning': ('The sealed predictions are compared with the registered run they describe.' if registered else
                        'The sealed predictions describe the registered fresh, live study. This run differs from '
                        'those conditions, so its statuses are recorded and are not the registered comparison.')}


def score(predictions, planned, observations):
    pass
    arms = {}
    for arm, entry in predictions.items():
        seen = list(observations.get(arm, []))
        complete = len(seen) == planned[arm]
        observed_counts = {}
        for item in seen:
            observed_counts[item['class']] = observed_counts.get(item['class'], 0) + 1
        components = {}
        if 'class_counts' in entry:
            _refuse(sum(entry['class_counts'].values()) == planned[arm], f'{arm}: prediction denominator differs from the plan')
            components['class_counts'] = (INCOMPLETE if not complete else
                                          MATCH if observed_counts == entry['class_counts'] else MISMATCH)
        else:
            components['class_counts'] = NOT_PREDICTED
        for name in FIELDS:
            if name not in entry:
                components[name] = NOT_PREDICTED
            elif any(item.get(name) != entry[name] or type(item.get(name)) is not type(entry[name]) for item in seen):
                components[name] = MISMATCH       
            else:
                components[name] = MATCH if complete else INCOMPLETE
        values = set(components.values())
        overall = (MISMATCH if MISMATCH in values else INCOMPLETE if INCOMPLETE in values
                   else NOT_PREDICTED if values == {NOT_PREDICTED} else MATCH)
        arms[arm] = {'prediction': entry, 'planned': planned[arm], 'observed': len(seen),
                     'observed_class_counts': observed_counts, 'components': components, 'status': overall,
                     'fully_predicted': NOT_PREDICTED not in values}
    statuses = [row['status'] for row in arms.values()]
    aggregate = (MISMATCH if MISMATCH in statuses else INCOMPLETE if INCOMPLETE in statuses
                 else NOT_PREDICTED if statuses and set(statuses) == {NOT_PREDICTED}
                 else MATCH if statuses else NOT_PREDICTED)
    return {'status': aggregate, 'arms': arms,
            'arms_predicted': sum(status != NOT_PREDICTED for status in statuses),
            'arms_not_predicted': sum(status == NOT_PREDICTED for status in statuses),
            'every_scheduled_arm_fully_predicted': all(row['fully_predicted'] for row in arms.values()),
            'scoring': 'per arm over final counts; blanks are NOT_PREDICTED; a mixed prediction is not scored per slot'}
