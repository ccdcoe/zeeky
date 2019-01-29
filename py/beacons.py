#!/usr/bin/env python3

from influxdb import InfluxDBClient 
#import matplotlib.pyplot as plt
#from scipy.stats import kurtosis
import numpy as np
from scipy.fftpack import fft, fftshift, fftfreq
import kafka
import json

LIMIT = 50
ALERT_LIMIT = 20 
TOPIC = 'cobalt-activity'

producer = kafka.KafkaProducer(bootstrap_servers = ['kafka-bootstrap.example.ex:9093'])

client = InfluxDBClient('localhost', 8086, 'root', 'root', 'telegraf')
series = client.query("show series from packet_int where resp_p = '80/tcp' or resp_p = '443/tcp' ")

def get_record(s):
    a = s.split(' AND ')
    r = {}
    for i in a:
        t = i.split('=')
        if t[0] in [ 'orig_h', 'resp_h', 'resp_p']:
            if t[0] == 'orig_h':
                t[0] = 'src'
            elif t[0] == 'resp_h':
                t[0] = 'dst'
            r[t[0]] = t[1][1:-1]
    t = r['resp_p'].split('/')
    del r['resp_p']
    r['p'] = t[0]
    r['proto'] = t[1]
    if ['p'] == 443:
        r['note'] = 'HTTPS'
    else:
        r['note'] = 'HTTP'

    return r

def kafka_msg(r):
    future = producer.send(TOPIC, json.dumps(r).encode('utf-8'))
    try:
        meta = future.get(timeout = 5)
    except kafka.KafkaError:
        print('Kafka sending failed')

kafka_msg({ 'msg': 'Started beacons.py'})

records = {}
for i in series['results']:
    s = i['key'].split(',')
    raw_params = [ j.split('=') for j in s[1:] if not j.startswith('path') and not j.startswith('host') ]
    params = [ j[0] + "='" + j[1] + "'" for j in raw_params ]
    qw = ' AND '.join(params)
    q = ("select intrvl from packet_int where " + qw + " and intrvl > 0.8 and time > now() - 3h order by time desc limit " + str(LIMIT))
    r = client.query(q)
    #print(raw_params)
    data = [ j['intrvl'] for j in r['packet_int'] ]
    if len(data) < 5:
        continue
    records[qw] = data
print("%d records acquired" % len(records))

for i in records:
    ratio = 1
    if sum(records[i]) / len(records[i]) > 100:
        if sum(records[i]) / len(records[i]) > 1000:
            ratio = 100
        else:
            ratio = 10

    a = [ [0] * int(10 * j / ratio - 1) + [10] for j in records[i] if j != 0 ]
    a = [ k for j in a for k in j ]
    yf = fft(a)
    freq = fftfreq(len(yf))
    maxlen = len(a) // 2 if len(a) < 2000 else 1000
#     if True:
#         plt.figure()
#         plt.title(i + (" %d items" % len(a)))
#         plt.plot(freq[:maxlen], np.abs(yf)[:maxlen])
    
    match = False
    #print(max(np.abs(yf)))
    for j in (enumerate(np.abs(yf)[:maxlen])):
        if j[0] > 1  and j[1] > LIMIT * ALERT_LIMIT / 10:
            r = get_record(i) 
            r['msg'] = 'Possible HTTP(S) beacon'
            r['likelihood'] = "%0.1f" % (10 * j[1] / LIMIT)
            r['period'] = "%0.1f" % (ratio * .1 / freq[j[0]])
            kafka_msg(r)

            #print("Possible beacon orig: %s, resp: %s, port: %s with estimated period frequency %0.1f, confidence %0.1f %%" % (r['orig_h'], r['resp_h'], r['resp_p'], .1 / freq[j[0]], 10*j[1]/LIMIT ))
            print("Possible beacon %s with estimated period %0.1f sec, confidence %0.1f %%" % (i, ratio * .1 / freq[j[0]], 10*j[1]/LIMIT ))

            #print(.1 / freq[j[0]])
            match = True
            break
    if not match:
        print("Not matched %s" % i)
    
   

#
