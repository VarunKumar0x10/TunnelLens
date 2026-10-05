import json
import math
from pathlib import Path
import pytest
from backend import classifier
from backend.classifier import classify_streams, forest_probabilities, load_model, model_card
from backend.features import FEATURE_NAMES, extract_window, stream_windows
from backend.parser import analyze_packets
from backend.reports import make_report

ROOT=Path(__file__).resolve().parents[1]


def test_known_window_feature_values():
    w=extract_window([(2,300,3),(0,100,1),(1,200,2)])
    f=w['features']
    assert f['packet_length_mean']==200 and f['packet_length_std']==pytest.approx(math.sqrt(20000/3))
    assert f['iat_mean']==1 and f['iat_std']==0 and f['iat_p90']==1
    assert f['duration']==2 and f['packet_rate']==1.5 and f['byte_rate']==300
    assert f['small_packet_fraction']==pytest.approx(2/3)
    assert f['idle_fraction']==1 and f['burst_fraction']==0
    assert w['first_packet']==1 and w['last_packet']==3 and not w['eligible']


def test_windows_nonoverlap_and_zero_duration():
    windows=stream_windows([(0,100,1),(9.99,200,2),(10,300,3),(20,500,4)])
    assert [w['packet_count'] for w in windows]==[2,1,1]
    assert extract_window([(1,100,i) for i in range(40)])['eligible'] is False
    assert all(math.isfinite(v) for v in extract_window([(1,100,1)])['features'].values())


def test_long_sparse_capture_bounded():
    with pytest.raises(ValueError,match='512'):
        stream_windows([(i*11,100,i) for i in range(513)])


@pytest.mark.parametrize('label',['real-time-like','bursty-streaming-like','bulk-transfer-like'])
def test_unseen_demo_prediction_uses_actual_features(label):
    path=ROOT/'samples'/'captures'/f'generated-{label}.pcap'
    collector={};summary,_,streams,_=analyze_packets(path,path.name,collector)
    result=classify_streams(collector,'generated_esp_benchmark')
    assert result['method']=='random_forest' and result['result']==label
    assert result['model_score']>=.7 and result['calibrated'] is False
    assert result['validation_status']=='synthetic_only'
    assert result['evaluation']['real_capture_validation'] is False
    assert all(set(w['features'])==set(FEATURE_NAMES) for w in result['windows'])


def test_new_real_upload_never_accepted_as_validated():
    path=ROOT/'samples'/'captures'/'generated-real-time-like.pcap'
    collector={};analyze_packets(path,path.name,collector)
    result=classify_streams(collector,'uploaded_capture')
    assert result['result']=='UNKNOWN' and result['model_score'] is None
    assert any(w['candidate_label']=='real-time-like' for w in result['windows'])
    assert result['accepted_windows']==0 and result['domain_status']=='unverified_capture'


def test_padded_demo_abstains():
    path=ROOT/'samples'/'captures'/'generated-out-of-envelope.pcap'
    r=make_report(path,path.name,'a'*32,'generated_esp_benchmark')
    assert r.inference['result']=='UNKNOWN' and r.inference['unknown_windows']>=2
    assert any('outside training envelope' in w['reason'] for w in r.inference['windows'])


def test_group_splits_and_class_support_are_disjoint():
    card=model_card();evaluation=card['evaluation']
    sets={k:set(v) for k,v in evaluation['split_groups'].items()}
    assert not sets['train']&sets['test'] and not sets['train']&sets['validation'] and not sets['test']&sets['validation']
    assert evaluation['split_counts']['test']['groups']==9
    assert evaluation['split_counts']['test']['windows']==36
    assert sum(map(sum,evaluation['confusion_matrix']))==36
    assert all(c['support']==6 for c in evaluation['per_configuration'])


def test_runtime_parity_on_saved_test_features():
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    rows=json.loads((ROOT/'models'/'benchmark_features.json').read_text())
    train=[r for r in rows if r['split']=='train'];test=[r for r in rows if r['split']=='test']
    model=RandomForestClassifier(n_estimators=80,max_depth=8,min_samples_leaf=2,class_weight='balanced',random_state=26160,n_jobs=1)
    model.fit([[r['features'][n] for n in FEATURE_NAMES] for r in train],[r['label'] for r in train])
    _,forest,_=load_model()
    expected=model.predict_proba([[r['features'][n] for n in FEATURE_NAMES] for r in test])
    actual=[forest_probabilities(forest,r['features']) for r in test]
    assert np.allclose(actual,expected,atol=1e-8)


def test_no_model_is_graceful(tmp_path,monkeypatch):
    load_model.cache_clear()
    try:
        monkeypatch.setattr(classifier,'MODEL_DIR',tmp_path)
        assert model_card()['available'] is False
        assert classify_streams({},'uploaded_capture')['result']=='UNKNOWN'
    finally:load_model.cache_clear()


def test_tampered_model_hash_rejected(tmp_path,monkeypatch):
    metadata=json.loads((ROOT/'models'/'metadata.json').read_text())
    (tmp_path/'metadata.json').write_text(json.dumps(metadata))
    (tmp_path/'forest.json').write_text((ROOT/'models'/'forest.json').read_text()+' ')
    (tmp_path/'evaluation.json').write_text((ROOT/'models'/'evaluation.json').read_text())
    load_model.cache_clear()
    try:
        monkeypatch.setattr(classifier,'MODEL_DIR',tmp_path)
        card=model_card()
        assert card['available'] is False and 'hash mismatch' in card['reason']
    finally:load_model.cache_clear()
