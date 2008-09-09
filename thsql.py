from decimal import Decimal
from NS2NewTraceSql import NS2NewTraceSql

mio = NS2NewTraceSql('prova.pta')

sent_pkts = mio.get_sent_pkts_times_at(1,1)
recv_pkts = mio.get_recv_pkts_times_at(0,1)

# id_sent_pkts = []

# for id, time in sent_pkts:
#     if id not in id_sent_pkts:
#         id_sent_pkts.append(id)
#     else:
#         print 'Duplicate id', id
        
# print len(id_sent_pkts)

start_time = Decimal(sent_pkts[0][1])
last_sent_pkt_id = sent_pkts[-1][0]

print 'Sent pkts at node',len(sent_pkts)
print 'Recv pkts at node',len(recv_pkts)

for recv_pkt in recv_pkts:
    if recv_pkt[0] == last_sent_pkt_id:
        stop_time = recv_pkt[1]

stop_time = Decimal(stop_time)
delta = stop_time - start_time

data_size = Decimal(mio.get_recv_flow_total_size_at(0,1,20))

th_bps = data_size / delta

conv = Decimal(8) / Decimal(1000)

th_kbps = th_bps*conv

print 'Throughtput',th_kbps

delay = Decimal('0')
for s,r in zip(sent_pkts,recv_pkts):
    delay += Decimal(r[1]) - Decimal(s[1])
    
avgDelay = delay / Decimal(len(recv_pkts))
print 'avgDelay', avgDelay * Decimal(1000)

jitter1 = Decimal(0)
prev_e2eDelay = Decimal(-1)

for s,r in zip(sent_pkts,recv_pkts):
    e2eDelay = Decimal(r[1]) - Decimal(s[1])

    if prev_e2eDelay == Decimal(-1):
        prev_e2eDelay = e2eDelay
    else:
        jitter1 += abs(e2eDelay - prev_e2eDelay)

jitter1 = jitter1*Decimal(1000)/Decimal(len(recv_pkts))
print 'Jitter1',jitter1

jitter2 = Decimal(0)
prev_delay = Decimal(0)

for i,r in enumerate(recv_pkts):
    delay = Decimal(r[1]) - Decimal(recv_pkts[i-1][1])
    jitter2 += abs(delay - prev_delay)
    prev_delay = delay

jitter2 = jitter2*Decimal(1000)/Decimal(len(recv_pkts))
print 'Jitter2',jitter2
