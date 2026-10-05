"""Train a real RF on explicitly synthetic ESP workloads; never claim field accuracy.

All timings and workloads are simulated. ESP payloads use actual AES via Scapy.
Complete base runs (including both cipher variants) share one split group.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from scapy.all import Ether, IP, UDP, Raw
from scapy.layers.ipsec import ESP, SecurityAssociation

from backend.features import FEATURE_NAMES, FEATURE_VERSION, stream_windows
from backend.parser import analyze_packets
from tools.generate_samples import write_capture

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data'/'training'
MODELS=ROOT/'models'
CLASSES=['real-time-like','bursty-streaming-like','bulk-transfer-like']
CONFIGS=['AES-GCM-256','AES-CBC-256-HMAC-SHA256']


def synthetic_schedule(label,seed,duration=20):
    rng=random.Random(seed);points=[];t=0.0
    if label=='real-time-like':
        interval=rng.uniform(.018,.038);base=rng.randint(90,230)
        while t<duration:
            points.append((t,max(50,int(rng.gauss(base,20)))))
            t+=max(.003,rng.gauss(interval,interval*.1))
    elif label=='bursty-streaming-like':
        while t<duration:
            for _ in range(rng.randint(18,65)):
                if t>=duration:break
                points.append((t,rng.randint(850,1280) if rng.random()>.1 else rng.randint(100,400)))
                t+=rng.uniform(.001,.006)
            t+=rng.uniform(.4,1.6)
    elif label=='bulk-transfer-like':
        interval=rng.uniform(.012,.042)
        while t<duration:
            points.append((t,rng.randint(950,1320) if rng.random()>.07 else rng.randint(100,300)))
            t+=rng.uniform(interval*.6,interval*1.4)
    else:  # deliberately outside training size envelope
        while t<duration:
            points.append((t,3800));t+=.025
    return points


def encrypted_packets(label,seed,config):
    rng=random.Random(seed)
    if config=='AES-GCM-256':
        sa=SecurityAssociation(ESP,spi=rng.randrange(1,2**32),crypt_algo='AES-GCM',crypt_key=os.urandom(36),
            tunnel_header=IP(src='192.0.2.50',dst='198.51.100.60'))
    else:
        sa=SecurityAssociation(ESP,spi=rng.randrange(1,2**32),crypt_algo='AES-CBC',crypt_key=os.urandom(32),
            auth_algo='SHA2-256-128',auth_key=os.urandom(32),
            tunnel_header=IP(src='192.0.2.50',dst='198.51.100.60'))
    packets=[]
    for i,(timestamp,size) in enumerate(synthetic_schedule(label,seed),1):
        payload=rng.randbytes(size)
        inner=IP(src='10.20.0.1',dst='10.30.0.2')/UDP(sport=20000,dport=30000)/Raw(payload)
        encrypted=sa.encrypt(inner)
        if i==1:
            assert sa.decrypt(encrypted.copy())[Raw].load==payload
            assert payload not in bytes(encrypted[ESP])
        packet=Ether(src='02:00:00:00:01:01',dst='02:00:00:00:02:02')/encrypted
        packet.time=1_791_200_000+seed*100+timestamp
        packets.append(packet)
    return packets


def json_write(path,value):
    path.write_text(json.dumps(value,indent=2,allow_nan=False),encoding='utf-8')


def export_forest(model):
    trees=[]
    for estimator in model.estimators_:
        tree=estimator.tree_;probabilities=[]
        for values in tree.value[:,0,:]:
            probabilities.append((values/values.sum()).tolist())
        trees.append({'left':tree.children_left.tolist(),'right':tree.children_right.tolist(),
            'feature':tree.feature.tolist(),'threshold':tree.threshold.tolist(),'probabilities':probabilities})
    return {'feature_names':FEATURE_NAMES,'classes':model.classes_.tolist(),'trees':trees}


def training_rows(manifest,root):
    """Reusable labeled-capture training path. Labels/provenance stay outside features."""
    rows=[];seen_hashes={};group_labels={}
    for entry in manifest:
        path=(root/entry['filename']).resolve()
        if not path.is_relative_to(root.resolve()):raise ValueError('Capture path escapes dataset root.')
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest!=entry['sha256']:raise ValueError('Training capture hash mismatch.')
        group=entry['group_id'];label=entry['label'];split=entry['split']
        if group in group_labels and group_labels[group]!=(label,split):raise ValueError('Group has inconsistent label or split.')
        group_labels[group]=(label,split)
        if digest in seen_hashes and seen_hashes[digest]!=group:raise ValueError('Duplicate capture in different groups.')
        seen_hashes[digest]=group
        collector={};analyze_packets(path,path.name,collector)
        for stream,points in collector.items():
            for window in stream_windows(points):
                if window['eligible']:
                    rows.append({'features':window['features'],'label':label,'group_id':group,'split':split,
                        'config':entry['config'],'capture_sha256':digest,'stream_id':stream})
    return rows


def train(rows,provenance):
    parts={name:[r for r in rows if r['split']==name] for name in ['train','validation','test']}
    for name,data in parts.items():
        if len({r['label'] for r in data})<3:raise ValueError(f'{name} must contain all three classes.')
    group_sets={name:{r['group_id'] for r in part} for name,part in parts.items()}
    assert not any(group_sets[a]&group_sets[b] for a,b in [('train','test'),('train','validation'),('test','validation')])
    X=lambda part:np.asarray([[r['features'][n] for n in FEATURE_NAMES] for r in part],dtype=float)
    y=lambda part:[r['label'] for r in part]
    model=RandomForestClassifier(n_estimators=80,max_depth=8,min_samples_leaf=2,class_weight='balanced',random_state=26160,n_jobs=1)
    model.fit(X(parts['train']),y(parts['train']))
    validation_probs=model.predict_proba(X(parts['validation']));validation_y=np.array(y(parts['validation']))
    val_pred=model.classes_[validation_probs.argmax(axis=1)]
    threshold=.70
    for candidate in [.70,.75,.80,.85,.90]:
        accepted=validation_probs.max(axis=1)>=candidate
        if accepted.any() and (val_pred[accepted]==validation_y[accepted]).mean()>=.9 and accepted.mean()>=.5:
            threshold=candidate;break
    predicted=model.predict(X(parts['test']));actual=y(parts['test'])
    matrix=confusion_matrix(actual,predicted,labels=model.classes_).tolist()
    by_config=[]
    for config in sorted({r['config'] for r in parts['test']}):
        for label in model.classes_:
            selected=[i for i,r in enumerate(parts['test']) if r['config']==config and r['label']==label]
            by_config.append({'config':config,'class':label,'support':len(selected),
                'recall':sum(predicted[i]==label for i in selected)/len(selected) if selected else None})
    all_training=X(parts['train']);bounds={}
    for i,name in enumerate(FEATURE_NAMES):
        lo,hi=float(all_training[:,i].min()),float(all_training[:,i].max())
        margin=max((hi-lo)*.35,abs(hi)*.15,.00001)
        bounds[name]=[max(0,lo-margin),hi+margin]
    evaluation={'domain':'Synthetic workload signatures with real ESP encryption and simulated timestamps',
        'real_capture_validation':False,'accuracy':float(accuracy_score(actual,predicted)),
        'macro_f1':float(f1_score(actual,predicted,average='macro')),
        'confusion_matrix':matrix,'classes':model.classes_.tolist(),
        'per_class':classification_report(actual,predicted,output_dict=True,zero_division=0),
        'per_configuration':by_config,
        'split_counts':{name:{'windows':len(part),'groups':len(group_sets[name]),'class_counts':dict(Counter(y(part)))} for name,part in parts.items()},
        'split_groups':{name:sorted(values) for name,values in group_sets.items()},
        'threshold_selection':'Validation split only; final test split not used for tuning.',
        'calibrated':False,'limitations':['Synthetic workload accuracy does not establish accuracy on real VPN applications.',
            'Shared generators can make this benchmark easier than field traffic. Grouped runs prevent window leakage but not generator bias.',
            'A feature-envelope check is a basic safeguard, not reliable out-of-distribution detection.']}
    MODELS.mkdir(exist_ok=True);forest=export_forest(model);json_write(MODELS/'forest.json',forest)
    json_write(MODELS/'benchmark_features.json',rows)
    metadata={'model_id':'tunnellens-rf-synthetic-v1','algorithm':'Random Forest (80 trees)',
        'created_at':datetime.now(timezone.utc).isoformat(),'feature_version':FEATURE_VERSION,'feature_names':FEATURE_NAMES,
        'classes':model.classes_.tolist(),'artifact_sha256':hashlib.sha256((MODELS/'forest.json').read_bytes()).hexdigest(),
        'training_domain':'synthetic_esp_workloads','validation_status':'synthetic_only','calibrated':False,
        'abstention_threshold':threshold,'feature_bounds':bounds,
        'feature_importance':sorted([{'feature':n,'importance':float(v)} for n,v in zip(FEATURE_NAMES,model.feature_importances_)],key=lambda x:-x['importance']),
        'provenance':provenance,'runtime_format':'Validated JSON trees; no pickle/joblib loading.'}
    json_write(MODELS/'metadata.json',metadata);json_write(MODELS/'evaluation.json',evaluation)
    from backend.classifier import forest_probabilities
    for values in X(parts['test']):
        actual_prob=model.predict_proba([values])[0]
        exported_prob=forest_probabilities(forest,dict(zip(FEATURE_NAMES,values)))
        assert np.allclose(actual_prob,exported_prob,atol=1e-8)
    return metadata,evaluation


def main():
    DATA.mkdir(parents=True,exist_ok=True);manifest=[]
    for label_id,label in enumerate(CLASSES):
        for run in range(16):
            group=f'class-{label_id}-run-{run:02d}'
            split='train' if run<10 else 'validation' if run<13 else 'test'
            seed=26160+label_id*100+run
            for config_id,config in enumerate(CONFIGS):
                name=f'{group}-cfg-{config_id}.pcap';path=DATA/name
                write_capture(path,encrypted_packets(label,seed,config))
                manifest.append({'filename':name,'group_id':group,'split':split,'label':label,'config':config,
                    'source_kind':'generated_esp_benchmark','sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        print(f'Generated encrypted synthetic runs: {label}',flush=True)
    json_write(DATA/'manifest.json',manifest)
    rows=training_rows(manifest,DATA);json_write(DATA/'features.json',rows)
    metadata,evaluation=train(rows,'Locally generated by tools/train_model.py. Simulated schedules/payloads, actual AES ESP encryption; no production traffic.')
    samples_path=ROOT/'samples'/'manifest.json'
    samples=json.loads(samples_path.read_text(encoding='utf-8'))
    samples=[s for s in samples if s['id'] in {'modern','legacy','esp-only'}]
    titles={'real-time-like':('Voice-like pattern','Regular small packets'),
        'bursty-streaming-like':('Streaming-like pattern','Large bursts and idle periods'),
        'bulk-transfer-like':('Bulk-transfer pattern','Sustained large packets'),
        'out-of-envelope':('Abstention challenge','Oversized padded traffic')}
    for i,label in enumerate(CLASSES+['out-of-envelope']):
        filename=f'generated-{label}.pcap';path=ROOT/'samples'/'captures'/filename
        # Unseen runs, outside train/validation/test; no shared generator seed.
        write_capture(path,encrypted_packets(label,80000+i*117,CONFIGS[i%2]))
        title,description=titles[label]
        samples.append({'id':label,'title':title,'description':description,'filename':filename,
            'source_kind':'generated_esp_benchmark','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'provenance':'Synthetic schedule/payloads encrypted as ESP with Scapy; local demo-only benchmark.',
            'ground_truth':label,'cipher_ground_truth':CONFIGS[i%2],
            'limitations':'Generated workload signatures; not real apps or a negotiated VPN. Ground truth is not passed to inference.'})
    json_write(samples_path,samples)
    print(json.dumps({'windows':len(rows),'synthetic_test_accuracy':evaluation['accuracy'],'synthetic_test_macro_f1':evaluation['macro_f1'],
        'threshold':metadata['abstention_threshold'],'real_validation':False},indent=2),flush=True)


if __name__=='__main__':main()
