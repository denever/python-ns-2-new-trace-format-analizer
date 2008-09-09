from decimal import Decimal
from NS2NewTraceSql import NS2NewTraceSql

mio = NS2NewTraceSql('prova.pta')

sent_pkts = mio.get_sent_pkts_times_at(1,1)
recv_pkts = mio.get_recv_pkts_times_at(0,1)

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
mio = int(0)
for s,r in zip(sent_pkts,recv_pkts):
    delay += Decimal(r[1]) - Decimal(s[1])
    mio += 1
    
avgDelay = delay / Decimal(mio)
print 'avgDelay', avgDelay * Decimal(1000)
