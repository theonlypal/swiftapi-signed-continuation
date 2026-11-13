
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from prediction_fixtures import prediction_bytes
from swiftapi_native_service.predictions import parse_predictions,select_for_run,score,comparison_scope

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prediction_evidence_tool',ROOT/'tools/verify_run.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)

def write(path,value):path.write_text(json.dumps(value))

@pytest.fixture
def fixture(tmp_path):
    raw=prediction_bytes(optional=False)
    parsed=parse_predictions(raw,V.MODEL)
    run,selected=select_for_run(parsed,'WITNESS_ONE',['VALID'])
    digest=hashlib.sha256(raw).hexdigest()
    config={'purpose':'DEVELOPMENT_QUALIFICATION','authority':'LIVE_SWIFTAPI','mode':'RECORDED_LOGITS_REPLAY','population':'WITNESS_ONE',
        'schedule':['VALID'],'repetitions':1,'author_predictions_sha256':digest,
        'predictions_sealed_at':'2026-01-01T00:00:00+00:00','predictions':selected}
    (tmp_path/'sealed-predictions.md').write_bytes(raw)
    write(tmp_path/'sealed-predictions-parsed.json',{'author_predictions_sha256':digest,
        'PRIMARY':parsed['PRIMARY'],'SECONDARY':parsed['SECONDARY'],'run':run,'selected_for_this_run':selected})
    write(tmp_path/'predictions-seal.json',{'author_predictions_sha256':digest,
        'predictions_sealed_at':config['predictions_sealed_at'],'predictions':selected})
    observation={'class':'R','output_bytes':1,'first_token':1,'generation_complete':False}
    payloads={'receipts/0000-VALID/receipt.json':{'execution_id':'synthetic-execution',
        'taxonomy':{'class':'R'},'output':'X','action':{'request':{'question':'synthetic question'}},
        'result':{'generated_token_ids':[1],'generation_complete':False}}}
    actual=score(selected,{'VALID':1},{'VALID':[observation]})
    actual['comparison_scope']=comparison_scope(config)
    write(tmp_path/'author-prediction-score.json',actual)
    summary={'planned_count':1,'rows':[{'slot':0,'arm':'VALID','question_index':0,
        'receipt':'receipts/0000-VALID/receipt.json','observation':observation,'question':'synthetic question'}],
        'author_prediction':actual}
    return tmp_path,config,summary,payloads

def test_reconstructs_from_bytes_and_verified_payloads(fixture):
    result=V.verify_predictions(*fixture)
    assert result['status']=='VERIFIED'
    assert result['score']['status']=='NOT_PREDICTED'

@pytest.mark.parametrize('fault',['file','config','parsed','seal','row','question','denominator','duplicate','score','omitted'])
def test_reconstruction_rejects_inconsistent_evidence(fixture,fault):
    root,config,summary,payloads=fixture
    if fault=='file':(root/'sealed-predictions.md').write_bytes(b'changed')
    elif fault=='config':config['predictions']={'VALID':{'class_counts':{'R':1}}}
    elif fault=='parsed':write(root/'sealed-predictions-parsed.json',{})
    elif fault=='seal':write(root/'predictions-seal.json',{})
    elif fault=='row':summary['rows'][0]['observation']['output_bytes']=999
    elif fault=='question':summary['rows'][0]['question']='another question'
    elif fault=='denominator':summary['planned_count']=2
    elif fault=='duplicate':summary['rows'].append(dict(summary['rows'][0]))
    elif fault=='score':write(root/'author-prediction-score.json',{})
    elif fault=='omitted':summary['rows']=[]
    with pytest.raises(ValueError):V.verify_predictions(root,config,summary,payloads)

def test_partial_coverage_scores_incomplete_without_fabrication(fixture):
    root,config,summary,_=fixture
    summary['rows']=[]
    actual=score(config['predictions'],{'VALID':1},{})
    actual['comparison_scope']=comparison_scope(config)
    summary['author_prediction']=actual
    write(root/'author-prediction-score.json',actual)
    assert V.verify_predictions(root,config,summary,{})['score']['arms']['VALID']['observed']==0

def test_old_local_replay_is_not_a_sealed_author_prediction(fixture):
    root,config,summary,payloads=fixture
    config['authority']='LOCAL_TEST_DOUBLE'
    assert V.verify_predictions(root,config,summary,payloads)['status']=='NOT_APPLICABLE_UNSEALED_LOCAL_REPLAY'

def test_model_pin_matches_runner():
    from swiftapi_native_service.experiment import MODEL
    assert V.MODEL==MODEL
