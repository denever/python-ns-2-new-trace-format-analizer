import sys
from decimal import Decimal
from NS2NewTraceSql import NS2NewTraceSql

class NetStats:
    def __init__(self, db):
        self.db = NS2NewTraceSql(db)

    
    def avg_stats(self, ip_src, ip_dst, flow_id, hdr_size):
        avg_tput, avg_delay, avg_jitter = 0,0,0
        
        sent_pkts = self.db.get_sent_pkts_times_at(ip_src, flow_id)
        recv_pkts = self.db.get_recv_pkts_times_at(ip_dst, flow_id)

        start_time = Decimal(sent_pkts[0][1])

        last_sent_pkt_id = sent_pkts[-1][0]
        last_recv_pkt_id = recv_pkts[-1][0]

        if last_recv_pkt_id == last_sent_pkt_id:
            stop_time = Decimal(recv_pkts[-1][1])
        else:
            print 'Packets not received in sequence'
            sys.exit(1)

        delta = stop_time - start_time
        data_size = Decimal(self.db.get_recv_flow_total_size_at(ip_dst, flow_id, hdr_size))
        th_bps = data_size / delta
        conv = Decimal(8) / Decimal(1000)
        
        avg_tput = th_bps*conv

        delay = Decimal('0')
        for s,r in zip(sent_pkts,recv_pkts):
            delay += Decimal(r[1]) - Decimal(s[1])
    
        avg_delay = delay * Decimal(1000) / Decimal(len(recv_pkts))

        jitter1 = Decimal(0)
        prev_e2eDelay = Decimal(-1)

        for s,r in zip(sent_pkts,recv_pkts):
            e2eDelay = Decimal(r[1]) - Decimal(s[1])

            if prev_e2eDelay == Decimal(-1):
                prev_e2eDelay = e2eDelay
            else:
                jitter1 += abs(e2eDelay - prev_e2eDelay)

        avg_jitter = jitter1*Decimal(1000)/Decimal(len(recv_pkts))

        return (avg_tput, avg_delay, avg_jitter)

    def avg_jitter2(self, ip_src, ip_dst, flow_id, pkt_size):
        sent_pkts = self.db.get_sent_pkts_times_at(ip_src, flow_id)
        recv_pkts = self.db.get_recv_pkts_times_at(ip_dst, flow_id)
        
        jitter2 = Decimal(0)
        prev_delay = Decimal(-1)

        for i,r in enumerate(recv_pkts):
            delay = Decimal(r[1]) - Decimal(recv_pkts[i-1][1])

            if prev_delay == Decimal(-1):
                jitter2 += abs(delay - prev_delay)

            prev_delay = delay

        return jitter2*Decimal(1000)/Decimal(len(recv_pkts))
    
if __name__ == '__main__':
    if len(sys.argv) == 2:
        input_file = sys.argv[1]
    else:
        print "usage thsql.py file.pta"
        sys.exit(1)

    mio = NetStats(input_file)
        
    (avg_tput, avg_delay, avg_jitter) = mio.avg_stats(1,0,1,20)

    print 'AvgThroughtput',round(avg_tput,3)

    print 'AvgDelay', round(avg_delay,3)

    print 'AvgJitter1',round(avg_jitter,3)
