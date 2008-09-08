from decimal import Decimal
from NS2NewTraceSql import NS2NewTraceSql

mio = NS2NewTraceSql('prova.pta')

sent_pkts = mio.get_sent_pkts_times_at(1,1,'MAC')
recv_pkts = mio.get_recv_pkts_times_at(0,1,'MAC')

start_time = Decimal(sent_pkts[0][1])
last_sent_pkt_id = sent_pkts[-1][0]

print len(sent_pkts), len(recv_pkts)

for recv_pkt in recv_pkts:
    if recv_pkt[0] == last_sent_pkt_id:
        stop_time = recv_pkt[1]

stop_time = Decimal(stop_time)
delta = stop_time - start_time

print start_time, stop_time, delta

data_size = Decimal(mio.get_recv_flow_total_size_at(0,1,20))

print data_size

th_bps = data_size / delta

conv = Decimal(8) / Decimal(1000)

th_kbps = th_bps*conv

print th_kbps

pippo = (data_size / Decimal(9)) * conv

print pippo

