"""Versioned directional ESP-window features, excluding endpoints, SPI and labels."""
import math
import statistics

FEATURE_VERSION = 'esp-directional-ipv4-v1'
WINDOW_SECONDS = 10.0
MIN_PACKETS = 30
FEATURE_NAMES = [
    'packet_length_mean','packet_length_std','packet_length_min','packet_length_max',
    'iat_mean','iat_std','iat_p90','duration','packet_rate','byte_rate',
    'small_packet_fraction','large_packet_fraction','idle_fraction','burst_fraction',
]


def percentile(values, p):
    if not values:return 0.0
    ordered=sorted(values);position=(len(ordered)-1)*p
    lo=int(position);hi=min(lo+1,len(ordered)-1)
    return ordered[lo]+(ordered[hi]-ordered[lo])*(position-lo)


def extract_window(points):
    """points = timestamp, outer-IP length, packet-index; sort before time differences."""
    ordered=sorted(points,key=lambda p:p[0])
    times=[float(p[0]) for p in ordered];lengths=[int(p[1]) for p in ordered]
    if not times:return None
    gaps=[b-a for a,b in zip(times,times[1:])]
    duration=times[-1]-times[0]
    mean=lambda v:statistics.fmean(v) if v else 0.0
    std=lambda v:statistics.pstdev(v) if len(v)>1 else 0.0
    features=dict(zip(FEATURE_NAMES,[mean(lengths),std(lengths),min(lengths),max(lengths),
        mean(gaps),std(gaps),percentile(gaps,.9),duration,
        len(points)/duration if duration>0 else 0.0,sum(lengths)/duration if duration>0 else 0.0,
        sum(x<256 for x in lengths)/len(lengths),sum(x>=1100 for x in lengths)/len(lengths),
        sum(x>=.2 for x in gaps)/len(gaps) if gaps else 0.0,
        sum(x<=.005 for x in gaps)/len(gaps) if gaps else 0.0]))
    valid=all(math.isfinite(x) for x in features.values()) and duration>0
    return {'features':features,'packet_count':len(points),'start':times[0],'end':times[-1],
        'first_packet':min(p[2] for p in ordered),'last_packet':max(p[2] for p in ordered),
        'eligible':valid and len(points)>=MIN_PACKETS,
        'reason':'' if valid and len(points)>=MIN_PACKETS else 'Too few packets or zero-duration window.'}


def stream_windows(points):
    if not points:return []
    baseline=min(p[0] for p in points);buckets={}
    for point in points:
        index=int((point[0]-baseline)//WINDOW_SECONDS)
        buckets.setdefault(index,[]).append(point)
        if len(buckets)>512:
            raise ValueError('More than 512 time windows in one stream. Filter a shorter capture.')
    return [dict(extract_window(buckets[index]),window_index=index,
        offset_seconds=round(index*WINDOW_SECONDS,3)) for index in sorted(buckets)]
