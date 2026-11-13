
import argparse
import base64
import json
import math
from pathlib import Path
from swiftapi.native_verify import (read_json, digest, encoded, require,
    verify_receipt as light_verify, SWIFTAPI_PUBLIC_KEY_B64, MODES)
AUTHORITY_KEY = SWIFTAPI_PUBLIC_KEY_B64
GATE_STATE_ABSOLUTE_TOLERANCE = 2.0 ** -21

def gate_state_comparison(recorded, calculated):
    """Binary32 scalar tolerance: one ULP in [4, 8), two in [2, 4)."""
    require(type(recorded) in (int, float) and type(calculated) in (int, float)
            and math.isfinite(recorded) and math.isfinite(calculated), 'Finite gate state')
    require(2 <= abs(calculated) < 8, 'Pinned gate state magnitude')
    difference = abs(recorded - calculated)
    require(difference <= GATE_STATE_ABSOLUTE_TOLERANCE, 'Gate state absolute tolerance')
    return {'recorded': recorded, 'recomputed': calculated,
            'absolute_difference': difference,
            'absolute_tolerance': GATE_STATE_ABSOLUTE_TOLERANCE, 'relative_tolerance': 0.0}

def verify_receipt(path, trusted_public_key, expected_mode, backend, *, expected_max_grant_age_seconds,
                   authority_key=None):
    import torch
    from .backend import EOS, VOCABULARY, LEARNED_GATE, VETO_AFTER_GATE, PCCG2Backend, REPLAY
    key = authority_key or AUTHORITY_KEY
    summary = light_verify(path,trusted_public_key,expected_mode,authority_key=key,
        expected_max_grant_age_seconds=expected_max_grant_age_seconds)
    row = read_json(path)['payload']
    if row['status'] == 'OPERATIONAL':
        return summary
    
    
    if next(backend._gate.parameters()).device.type != 'cpu':
        backend = PCCG2Backend(backend._source,backend._content_dir,backend._harness,
                              REPLAY,full_model=False)
    result, request = row['result'], row['action']['request']
    require(request['question'] in backend.allowed_questions,'Question outside pinned bank')
    bank = backend._bank[backend._index[request['question']]]
    require(result['question_id'] == bank['question_id'] and result['question_sha256'] == digest(request['question'].encode()),'Question provenance')
    require(result['input_ids'] == bank['input_ids'] and result['archived_input_ids_sha256'] == digest(encoded(bank['input_ids'])),'Pinned input IDs')
    inputs = backend.prompt_artifacts(request['question'])
    require((Path(path).parent/'prompt.utf8.bin').read_bytes() == inputs['rendered_prompt'],'Pinned rendered prompt')
    for name in ('revision','base_revision','gate_sha256','tokenizer_json_sha256','bank_sha256','native_eos','vocabulary',
                 'repository','base_model','content_identity_sha256','gate_trainable_parameters','gate_gain',
                 'original_model_py_sha256','original_core_py_sha256','release_config_sha256',
                 'bank_first_logits_sha256','bank_questions','source_manifest_sha256','upstream_manifest_sha256',
                 'system_prompt_sha256','permission_sign','permission_values','gate_conditions','gate_condition_token_ids',
                 'september_archive_check','content_dtype','gate_dtype'):
        require(row['action']['profile'][name] == backend.metadata[name],'Pinned identity '+name)
    tokens = result['generated_token_ids']
    require(result['september_archive_non_eos_sha256'] == bank['nonEOS_bf16_sha256'],'Archive comparison source')
    require(result['first_step_non_eos_matches_september_archive'] is
            (result['steps'][0]['non_eos_sha256'] == bank['nonEOS_bf16_sha256']),'Archive comparison outcome')
    visible = tokens[:-1] if tokens[-1] == EOS else tokens
    raw = backend._tokenizer.decode(visible,skip_special_tokens=False).encode() if visible else b''
    require(raw == (Path(path).parent/'output.bin').read_bytes(),'Token decode differs from output')
    require(result['later_tokens'] == ('NOT_GENERATED' if expected_mode == MODES[0] else 'GENERATED_FRESH'),'Later-token provenance')
    require(result['input_ids_role'] == ('IDENTIFIES_ARCHIVED_VECTOR_NOT_FED_TO_MODEL' if expected_mode == MODES[0] else 'FED_TO_MODEL'),'Input role')
    def raw_bytes(t):
        return t.contiguous().view(torch.uint8).numpy().tobytes()
    def non_eos(t):
        return torch.cat((t[:EOS],t[EOS+1:]))
    for i, step in enumerate(result['steps']):
        stock, selected = [torch.frombuffer(bytearray((Path(path).parent/f'{i}-{kind}.bf16.bin').read_bytes()),dtype=torch.bfloat16).clone() for kind in ('stock','selected')]
        if i == 0:
            if expected_mode == MODES[0]:
                require(raw_bytes(stock) == raw_bytes(backend._logits[backend._index[request['question']]]),'Not authentic archived vector')
            model = backend._module.SeparatedContinuationModel(torch.nn.Identity(),backend._gate)
            ids = torch.tensor([backend._module.condition_tokens(result['gate_condition'])])
            with torch.inference_mode():
                transformed,state = model.boundary(stock[None],ids,True,1.0)
            calculated = transformed[0].clone()
            intervention = LEARNED_GATE
            cause = 'LEARNED_GATE' if int(calculated.float().argmax()) == EOS and int(stock.float().argmax()) != EOS else 'NONE'
            if result['permission'] == 'PERMISSION_NOT_VERIFIED' and int(calculated.float().argmax()) != EOS:
                maximum = non_eos(calculated).float().max()
                calculated[EOS] = (maximum+maximum.abs().clamp(min=1)).to(calculated.dtype)
                intervention,cause = VETO_AFTER_GATE,'VETO'
            summary['gate_state_comparison'] = gate_state_comparison(step['permission_state'], float(state[0]))
            require(result['stop_cause'] == cause,'Stop cause')
            require(result['stock_first_token_is_eos'] is (int(stock.float().argmax()) == EOS),'Stock EOS flag')
            require(result['archived_first_token'] == bank['generated_ids'][0],'Archive first token')
            require(result['first_token_matches_archive'] is (None if tokens[0] == EOS else tokens[0] == bank['generated_ids'][0]),'Archive comparison flag')
        else:
            calculated,intervention = stock,'NONE'
            require(step['permission_state'] is None,'Later gate state')
        require(raw_bytes(calculated) == raw_bytes(selected),'Numerical boundary replay')
        require(step['intervention'] == intervention,'Intervention label')
    summary['numerical_replay'] = 'PASS'
    summary['numerical_boundary_replay'] = 'PASS'
    summary['archived_score_source'] = 'VERIFIED' if expected_mode == MODES[0] else 'NOT_A_FRESH_FORWARD_REPRODUCTION'
    return summary

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('receipt',type=Path)
    p.add_argument('--trusted-key',required=True,type=Path)
    p.add_argument('--expected-mode',required=True,choices=MODES)
    p.add_argument('--expected-max-grant-age-seconds',required=True,type=float)
    for name in ('source','content','harness'):
        p.add_argument('--'+name,required=True,type=Path)
    a=p.parse_args()
    from .backend import PCCG2Backend
    
    backend=PCCG2Backend(a.source,a.content,a.harness,MODES[0],full_model=False)
    try:
        result=verify_receipt(a.receipt,read_json(a.trusted_key)['public_key'],a.expected_mode,backend,
            expected_max_grant_age_seconds=a.expected_max_grant_age_seconds)
    except Exception as exc:
        print(json.dumps({'status':'FAIL','reason':str(exc)}));raise SystemExit(2)
    print(json.dumps(result,sort_keys=True))
if __name__ == '__main__':
    main()
