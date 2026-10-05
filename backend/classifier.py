"""Safe JSON Random Forest inference, with explicit training-domain restrictions.

No pickle/joblib deserialization is used. The JSON artifact is exported from a
locally trained sklearn forest, not a hand-coded heuristic.
"""
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path

from .features import FEATURE_NAMES, FEATURE_VERSION, stream_windows

MODEL_DIR=Path(__file__).resolve().parents[1]/'models'


def _read_json(name):
    path=MODEL_DIR/name
    if not path.exists() or path.stat().st_size>20*1024*1024:
        raise ValueError('Model artifact missing or too large.')
    return json.loads(path.read_text(encoding='utf-8'))


@lru_cache(maxsize=2)
def load_model():
    metadata=_read_json('metadata.json');forest=_read_json('forest.json');evaluation=_read_json('evaluation.json')
    if metadata['feature_version']!=FEATURE_VERSION or forest['feature_names']!=FEATURE_NAMES:
        raise ValueError('Model feature schema does not match this analyzer.')
    if hashlib.sha256((MODEL_DIR/'forest.json').read_bytes()).hexdigest()!=metadata['artifact_sha256']:
        raise ValueError('Model artifact hash mismatch.')
    if len(forest['trees']) not in range(1,301) or len(forest['classes']) not in range(2,11):
        raise ValueError('Unsupported model dimensions.')
    for tree in forest['trees']:
        count=len(tree['left'])
        if not 0<count<=8192 or any(len(tree[k])!=count for k in ['right','feature','threshold','probabilities']):
            raise ValueError('Invalid tree array lengths.')
        for i in range(count):
            if tree['left'][i] == -1:
                p=tree['probabilities'][i]
                if len(p)!=len(forest['classes']) or any(not math.isfinite(x) or x<0 for x in p) or abs(sum(p)-1)>1e-5:
                    raise ValueError('Invalid leaf probabilities.')
            elif not (0<=tree['feature'][i]<len(FEATURE_NAMES) and i<tree['left'][i]<count and i<tree['right'][i]<count and math.isfinite(tree['threshold'][i])):
                raise ValueError('Invalid tree branch.')
    return metadata,forest,evaluation


def model_card():
    try:
        metadata,_,evaluation=load_model()
        return {'available':True,**metadata,'evaluation':evaluation}
    except (ValueError,KeyError,TypeError,json.JSONDecodeError,OSError) as exc:
        return {'available':False,'reason':str(exc),'validation_status':'unavailable'}


def forest_probabilities(forest,features):
    # sklearn tree inputs use float32. Match that rounding without loading sklearn.
    import struct
    vector=[struct.unpack('f',struct.pack('f',features[n]))[0] for n in FEATURE_NAMES]
    result=[0.0]*len(forest['classes'])
    for tree in forest['trees']:
        node=0
        while tree['left'][node]!=-1:
            node=tree['left'][node] if vector[tree['feature'][node]]<=tree['threshold'][node] else tree['right'][node]
        for i,p in enumerate(tree['probabilities'][node]):result[i]+=p/len(forest['trees'])
    return result


def classify_streams(collector,source_kind):
    windows=[]
    card=model_card()
    if not card['available']:
        return {'method':'unavailable','result':'UNKNOWN','model_score':None,'reason':card['reason'],
                'validation_status':'unavailable','windows':[],'streams':[]}
    metadata,forest,_=load_model()
    known_demo=source_kind in {'synthetic_fixture','generated_esp_benchmark'}
    aggregate={};counts={};stream_results=[]
    for stream_id,points in collector.items():
        stream_counts={}
        try:stream_data=stream_windows(points)
        except ValueError:
            stream_results.append({'stream_id':stream_id,'result':'UNKNOWN','accepted_windows':0,'window_count':0,
                'reason':'Too many windows; use a shorter capture.'})
            continue
        if len(windows)+len(stream_data)>4096:
            stream_results.append({'stream_id':stream_id,'result':'UNKNOWN','accepted_windows':0,'window_count':len(stream_data),
                'reason':'Inference window limit reached.'})
            continue
        for window in stream_data:
            values=window['features'];probs=None;candidate=None;score=None;result='UNKNOWN'
            reason=window['reason']
            if window['eligible']:
                probs=forest_probabilities(forest,values)
                winner=max(range(len(probs)),key=probs.__getitem__)
                candidate=forest['classes'][winner];score=probs[winner]
                outside=[name for name in FEATURE_NAMES if not metadata['feature_bounds'][name][0]<=values[name]<=metadata['feature_bounds'][name][1]]
                if outside:reason='Feature distribution outside training envelope: '+', '.join(outside[:3])+'.'
                elif score<metadata['abstention_threshold']:reason='Model score below the abstention threshold.'
                elif not known_demo:reason='Real-capture validation pending; experimental candidate only.'
                else:result=candidate;reason='Synthetic workload signature prediction; not real application validation.'
            output={**window,'stream_id':stream_id,'result':result,'candidate_label':candidate,
                'model_score':None if score is None else round(score,4),
                'probabilities':{} if probs is None else {label:round(p,4) for label,p in zip(forest['classes'],probs)},
                'reason':reason,'domain_status':'synthetic_demo' if known_demo else 'unverified_capture'}
            windows.append(output)
            if result!='UNKNOWN':
                counts[result]=counts.get(result,0)+1
                aggregate[result]=aggregate.get(result,0)+score
                stream_counts[result]=stream_counts.get(result,0)+1
        labels=sorted(stream_counts,key=stream_counts.get,reverse=True)
        stream_results.append({'stream_id':stream_id,'result':labels[0] if len(labels)==1 else 'MIXED' if labels else 'UNKNOWN',
            'accepted_windows':sum(stream_counts.values()),'window_count':sum(w['stream_id']==stream_id for w in windows)})
    ordered=sorted(counts,key=counts.get,reverse=True)
    overall=ordered[0] if len(ordered)==1 else 'MIXED' if ordered else 'UNKNOWN'
    score=round(aggregate[overall]/counts[overall],4) if overall in counts else None
    return {'method':'random_forest','result':overall,'model_score':score,
        'reason':'Local Random Forest applied to directional ESP size/timing windows. Trained and evaluated on synthetic workloads only.',
        'validation_status':'synthetic_only','model_id':metadata['model_id'],'feature_version':FEATURE_VERSION,
        'domain_status':'synthetic_demo' if known_demo else 'unverified_capture',
        'abstention_threshold':metadata['abstention_threshold'],'calibrated':False,
        'accepted_windows':sum(counts.values()),'unknown_windows':sum(w['result']=='UNKNOWN' for w in windows),
        'classes':forest['classes'],'streams':stream_results,'windows':windows,
        'evaluation':card['evaluation'],'feature_importance':metadata['feature_importance']}
