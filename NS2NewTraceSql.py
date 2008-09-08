#! /usr/bin/env python
# -*- Python -*-
###########################################################################
#                           NS2NewTraceParser                             #
#                        --------------------                             #
#  copyright         (C) 2008  Giuseppe "denever" Martino                 #
#  email                : denever@users.sf.net                            #
###########################################################################
###########################################################################
#                                                                         #
#   This program is free software; you can redistribute it and/or modify  #
#   it under the terms of the GNU General Public License as published by  #
#   the Free Software Foundation; either version 2 of the License, or     #
#   (at your option) any later version.                                   #
#                                                                         #
#  This program is distributed in the hope that it will be useful,        #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of         #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
#  GNU General Public License for more details.                           #
#                                                                         #
#  You should have received a copy of the GNU General Public License      #
#  along with this program; if not, write to the Free Software            #
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA#
#                                                                         #
###########################################################################

import re
import sys
import sqlite3
import os.path

find_send_event = re.compile("^s")
find_recv_event = re.compile("^r")
find_drop_event = re.compile("^d")
find_fwrd_event = re.compile("^t")

get_event_time = re.compile("-t ([0-9.]*)")

get_node_id = re.compile("-Ni (\d+)")
get_node_pos = re.compile("-Nx (\d+) -Ny (\d+) -Nz (\d+)")
get_node_nrg = re.compile("-Ne (-[0-9.]*)")

get_trace_lvl = re.compile("-Nl ([A-Z]+)")
get_event_rsn = re.compile("-Nw ([A-Z]+)")

get_pktip_src = re.compile("-Is (\d+).(\d+)")
get_pktip_dst = re.compile("-Id (\d+).(\d+)")
get_pktip_type = re.compile("-It ([a-z]+)")
get_pktip_size = re.compile("-Il (\d+)")
get_pktip_flwid = re.compile("-If (\d+)")
get_pktip_unqid = re.compile("-Ii (\d+)")
get_pktip_ttl = re.compile("-Iv (\d+)")

get_nxhop_sid = re.compile("-Hs (\d+)")
get_nxhop_did = re.compile("-Hd (\d+)")

get_pkmac_dur = re.compile("-Ma (\d+)")
get_pkmac_dst = re.compile("-Md (\w+)")
get_pkmac_src = re.compile("-Ms (\w+)")
get_pkmac_type = re.compile("-Mt (\d+)")

get_pkapp_proto = re.compile('-Pn (\w+)')
get_pkapp_sqn = re.compile("-Pi (\d+)")
get_pkapp_fwd = re.compile("-Pf (\d+)")
get_pkapp_opt = re.compile("-Po (\d+)")

trace_lvl_agt = re.compile("-Nl AGT")
trace_lvl_rtr = re.compile("-Nl RTR")
trace_lvl_rtr = re.compile("-Nl MAC")

app_proto_arp = re.compile('-Pn arp')
app_proto_dsr = re.compile('-Pn dsr')
app_proto_cbr = re.compile('-Pn cbr')
app_proto_tcp = re.compile('-Pn tcp')


class NS2NewTraceSql:
    """
    This class parse the new trace parser
    Open a file and pass it to the constructor
    trace_file = open('trace_file.tr','r')
    parser = NSNewTraceParser(trace_file)
    then you could use methods
    """
    create_send_event_table = """create table send_events 
(time text,
 nodeid integer,
 tracelvl text,
 reason text,
 ip_src text,
 ip_src_prt integer,
 ip_dst text,
 ip_dst_prt integer,
 ip_type text,
 ip_size integer,
 flowid integer,
 uniqid integer,
 ip_ttl integer,
 pkt_app text)"""

    create_recv_event_table = """create table recv_events 
(time text,
 nodeid integer,
 tracelvl text,
 reason text,
 ip_src text,
 ip_src_prt integer,
 ip_dst text,
 ip_dst_prt integer,
 ip_type text,
 ip_size integer,
 flowid integer,
 uniqid integer,
 ip_ttl integer,
 pkt_app text)"""

    create_drop_event_table = """create table drop_events 
(time text,
 nodeid integer,
 tracelvl text,
 reason text,
 ip_src text,
 ip_src_prt integer,
 ip_dst text,
 ip_dst_prt integer,
 ip_type text,
 ip_size integer,
 flowid integer,
 uniqid integer,
 ip_ttl integer,
 pkt_app text)"""

    create_fwrd_event_table = """create table fwrd_events 
(time text,
 nodeid integer,
 tracelvl text,
 reason text,
 ip_src text,
 ip_src_prt integer,
 ip_dst text,
 ip_dst_prt integer,
 ip_type text,
 ip_size integer,
 flowid integer,
 uniqid integer,
 ip_ttl integer,
 pkt_app text)"""

    insert_send_event = "insert into send_events values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    insert_recv_event = "insert into recv_events values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    insert_drop_event = "insert into drop_events values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    insert_fwrd_event = "insert into fwrd_events values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

    def __init__(self, db_name, input_filename = None):
        self.database_name = db_name

        if input_filename != None and os.path.exists(self.database_name):
            os.remove(self.database_name)

        self.conn = sqlite3.connect(self.database_name)
        
        if input_filename == None:
            return

        c = self.conn.cursor()

        c.execute(self.create_send_event_table)
        c.execute(self.create_recv_event_table)
        c.execute(self.create_drop_event_table)
        c.execute(self.create_fwrd_event_table)        
        self.conn.commit()
        
        input_file = open(input_filename, 'r')
        input_lines = input_file.readlines()

        for line in input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)
            fwrd_event_found = find_fwrd_event.search(line)

            time = get_event_time.search(line).group(1)
            node_id = get_node_id.search(line).group(1)
            tracelvl = get_trace_lvl.search(line).group(1)
            
            event_rsn_found = get_event_rsn.search(line)
            event_rsn = event_rsn_found.group(1) if event_rsn_found else None
            
            ip_src_found = get_pktip_src.search(line)
            ip_src = ip_src_found.group(1) if ip_src_found else None
            ip_src_prt = int(ip_src_found.group(2)) if ip_src_found else None
            
            ip_dst_found = get_pktip_dst.search(line)
            ip_dst = ip_dst_found.group(1) if ip_dst_found else None
            ip_dst_prt = int(ip_dst_found.group(1)) if ip_dst_found else None            
            
            ip_type_found = get_pktip_type.search(line)
            ip_type = ip_type_found.group(1) if ip_type_found else None
            
            ip_size_found = get_pktip_size.search(line)
            ip_size = int(ip_size_found.group(1)) if ip_size_found else None
            
            flowid_found = get_pktip_flwid.search(line)
            flowid = int(flowid_found.group(1)) if flowid_found else None
            
            uniqid_found = get_pktip_unqid.search(line)
            uniqid = int(uniqid_found.group(1)) if uniqid_found else None

            ip_ttl_found = get_pktip_ttl.search(line)
            ip_ttl = int(ip_ttl_found.group(1)) if ip_ttl_found else None
            
            app_found = get_pkapp_proto.search(line)
            app = app_found.group(1) if app_found else None
            
            t = (time, int(node_id), tracelvl, event_rsn, ip_src, ip_src_prt, ip_dst, ip_dst_prt, ip_type, ip_size, flowid, uniqid, ip_ttl, app)
            
            if send_event_found:
                c.execute(self.insert_send_event, t)

            if recv_event_found:
                c.execute(self.insert_recv_event, t)

            if drop_event_found:
                c.execute(self.insert_drop_event, t)

            if fwrd_event_found:
                c.execute(self.insert_fwrd_event, t)
            
        self.conn.commit()
        c.close()

    def get_nodes(self):
        c = self.conn.cursor()
        c.execute('select nodeid from send_events where nodeid not null group by nodeid')
        nodes = [nodeid[0] for nodeid in c]
        c.close()
        return nodes

    def get_flows(self):
        c = self.conn.cursor()
        c.execute('select flowid from send_events where flowid not null group by flowid')
        flowids = [flowid[0] for flowid in c]
        c.close()
        return flowids        

    def get_src_dst_per_flow(self):
        c = self.conn.cursor()
        c.execute('select ip_src, ip_dst, flowid from send_events where flowid not null group by flowid')

        src_dst = {}
        
        for data in c:
            src_dst[data[2]] = (data[0], data[1])
            
        c.close()
        return src_dst                        

    def get_flow_types(self):
        c = self.conn.cursor()
        c.execute('select pkt_app, flowid from send_events where flowid not null group by flowid')
        
        flow_types = {}

        for data in c:
            flow_types[data[1]] = data[0]
        
        return flow_types
    
    def get_pkt_iptypes(self):
        """
        Returns a list of package ip types (-It) present in the trace file
        example: types = parser.get_pkt_iptypes()
        """
        known_types = []
        
        c = self.conn.cursor()

        c.execute('select ip_type from send_events where ip_type not null group by ip_type')
        for data in c:
            known_types.append(data[0])
        
        c.execute('select ip_type from recv_events where ip_type not null group by ip_type')
        for data in c:
            if data[0] not in known_types:
                known_types.append(data[0])

        c.execute('select ip_type from drop_events where ip_type not null group by ip_type')        
        for data in c:
            if data[0] not in known_types:
                known_types.append(data[0])

        c.execute('select ip_type from fwrd_events where ip_type not null group by ip_type')
        for data in c:
            if data[0] not in known_types:
                known_types.append(data[0])

        return known_types

    def get_trace_of(self, unique_id):
        """
        Return a list of trace lines for the package with unique_id
        example: print parser.get_trace_of('1')
        """
        pkt_trace = []
        c = self.conn.cursor()

        c.execute('select "sent",* from send_events where uniqid = %d' % int(unique_id))
        for data in c:
            pkt_trace.append(data)

        c.execute('select "recv",* from recv_events where uniqid = %d' % int(unique_id))
        for data in c:
            pkt_trace.append(data)
            
        c.execute('select "drop",* from drop_events where uniqid = %d' % int(unique_id))
        for data in c:
            pkt_trace.append(data)

        c.execute('select "fwrd",* from fwrd_events where uniqid = %d' % int(unique_id))
        for data in c:
            pkt_trace.append(data)
            
        return pkt_trace
                
    def count_recv_pkt_at_node(self, node_id):
        """
        Returns the number of packages received at the node node_id
        example: num_recv_pkts = parser.count_recv_pkt_at_node('1')
        """
        c = self.conn.cursor()

        c.execute('select count(*) from recv_events where nodeid = %d' % int(node_id))

        return c.fetchone()[0]

    def get_pkts_at_macdst(self, mac_dest):
        """
        Returns unique_id of packages with mac destination == mac_dest
        example: parser.get_pkts_at_macdst('fffff')
        """
        sent_pkt = []
        recv_pkt = []
        drop_pkt = []
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)            

            if send_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    macdst = get_pkmac_dst.search(line)
                    if macdst.group(1) == mac_dest:
                        seqnum = get_pktip_unqid.search(line)
                        if seqnum != None:
                            if seqnum.group(1) != None:
                                sent_pkt.append(seqnum.group(1))
                
            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    macdst = get_pkmac_dst.search(line)
                    if macdst.group(1) == mac_dest:
                        seqnum = get_pktip_unqid.search(line)
                        if seqnum != None:
                            if seqnum.group(1) != None:
                                recv_pkt.append(seqnum.group(1))

            if drop_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    macdst = get_pkmac_dst.search(line)
                    if macdst.group(1) == mac_dest:
                        seqnum = get_pktip_unqid.search(line)
                        if seqnum != None:
                            if seqnum.group(1) != None:
                                drop_pkt.append(seqnum.group(1))

        return (sent_pkt, recv_pkt, drop_pkt)
                        
    def get_pkts_at_lvl(self, lvl):
        """
        Returns a tuple of three lists of sent, received, dropped packets at level lvl ('MAC','AGT','RTR')
        example: (sent_pkt, recv_pkt, drop_pkt) = parser.get_pkts_at_lvl('MAC')
        """
        c = self.conn.cursor()
        c.execute("select uniqid from send_events where tracelvl = '%s'" % lvl)

        sent_packets = [uniqid[0] for uniqid in c]
        
        c.execute("select uniqid from recv_events where tracelvl = '%s'" % lvl)
        recv_packets = [uniqid[0] for uniqid in c]
        
        c.execute("select uniqid from drop_events where tracelvl = '%s'" % lvl)        
        drop_packets = [uniqid[0] for uniqid in c]

        c.close()

        return (sent_packets, recv_packets, drop_packets)

    def get_pkts_flowid(self, flowid, lvl = 'MAC'):
        """
        Returns a tuple of three lists of sent, received, dropped packets with flow id = flowid
        and at level lvl ('MAC','AGT','RTR') default lvl is 'MAC'
        example: (sent_pkt, recv_pkt, drop_pkt) = parser.get_pkts_flowid('MAC')
        """
        c = self.conn.cursor()
        c.execute("select uniqid from send_events where tracelvl = '%s' and flowid = %d" % (lvl, flowid))
        sent_packets = [uniqid[0] for uniqid in c]
        
        c.execute("select uniqid from recv_events where tracelvl = '%s' and flowid = %d" % (lvl, flowid))
        recv_packets = [uniqid[0] for uniqid in c]
        
        c.execute("select uniqid from drop_events where tracelvl = '%s' and flowid = %d" % (lvl, flowid))
        drop_packets = [uniqid[0] for uniqid in c]

        c.close()
        return (sent_packets, recv_packets, drop_packets)

    def get_trace_maconly_pkts(self):
        """
        Returns a tuple of three lists of trace lines of sent, received, dropped MAC level packages
        example: lines = parser.get_trace_maconly_pkts()
        """
        
        sent_macpkt = []
        recv_macpkt = []
        drop_macpkt = []
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)            

            if send_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum == None:
                        sent_macpkt.append(line)

            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum == None:
                        recv_macpkt.append(line)

            if drop_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum == None:
                        drop_macpkt.append(line)

        return (sent_macpkt, recv_macpkt, drop_macpkt)

    
    def get_sent_bursts_per_flow(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times per sent flowid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_flowid = None
        last_time = float()
        start_burst_times = {}
        stop_burst_times = {}
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            trac_lvl_found = get_trace_lvl.search(line)
            if send_event_found != None and trac_lvl_found != None:
                if trac_lvl_found.group(1) == lvl:
                    flowid_found = get_pktip_flwid.search(line)
                    time_found = get_event_time.search(line)
                    if flowid_found != None and time_found != None:
                        new_flowid = flowid_found.group(1)
                        time = float(time_found.group(1))
                        if new_flowid != last_flowid:
                            if not start_burst_times.has_key(new_flowid):
                                start_burst_times[new_flowid] = []

                            start_burst_times[new_flowid].append(time)

                            if not stop_burst_times.has_key(last_flowid):
                                stop_burst_times[last_flowid] = []

                            stop_burst_times[last_flowid].append(last_time)

                        last_flowid = new_flowid
                        last_time = time
                            
        return (start_burst_times, stop_burst_times)

    def get_sent_bursts_per_node(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times of pkt sent per nodeid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_nodeid = None
        last_time = None
        start_burst_times = {}
        stop_burst_times = {}
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            trac_lvl_found = get_trace_lvl.search(line)
            if send_event_found != None and trac_lvl_found != None:
                if trac_lvl_found.group(1) == lvl:
                    nodeid_found = get_node_id.search(line)
                    time_found = get_event_time.search(line)
                    if nodeid_found != None and time_found != None:
                        new_nodeid = nodeid_found.group(1)
                        time = time_found.group(1)
                        if new_nodeid != last_nodeid:
                            if not start_burst_times.has_key(new_nodeid):
                                start_burst_times[new_nodeid] = []

                            start_burst_times[new_nodeid].append(time)

                            if not stop_burst_times.has_key(last_nodeid):
                                stop_burst_times[last_nodeid] = []

                            stop_burst_times[last_nodeid].append(last_time)
                            
                        last_nodeid = new_nodeid
                        last_time = time
                        
        return (start_burst_times, stop_burst_times)

    def get_recv_bursts_per_flow(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times per received flowid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_flowid = None
        last_time = float()
        start_burst_times = {}
        stop_burst_times = {}
        
        for line in self.input_lines:
            recv_event_found = find_recv_event.search(line)
            trac_lvl_found = get_trace_lvl.search(line)
            if recv_event_found != None and trac_lvl_found != None:
                if trac_lvl_found.group(1) == lvl:
                    flowid_found = get_pktip_flwid.search(line)
                    time_found = get_event_time.search(line)
                    if flowid_found != None and time_found != None:
                        new_flowid = flowid_found.group(1)
                        time = float(time_found.group(1))
                        if new_flowid != last_flowid:
                            if not start_burst_times.has_key(new_flowid):
                                start_burst_times[new_flowid] = []

                            start_burst_times[new_flowid].append(time)

                            if not stop_burst_times.has_key(last_flowid):
                                stop_burst_times[last_flowid] = []

                            stop_burst_times[last_flowid].append(last_time)

                        last_flowid = new_flowid
                        last_time = time
                            
        return (start_burst_times, stop_burst_times)

    def get_recv_bursts_per_node(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times of pkt recv per nodeid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_recv_bursts_per_flow()
        """
        last_nodeid = None
        last_time = float()
        start_burst_times = {}
        stop_burst_times = {}
        
        for line in self.input_lines:
            recv_event_found = find_recv_event.search(line)
            trac_lvl_found = get_trace_lvl.search(line)
            if recv_event_found != None and trac_lvl_found != None:
                if trac_lvl_found.group(1) == lvl:
                    nodeid_found = get_node_id.search(line)
                    time_found = get_event_time.search(line)
                    if nodeid_found != None and time_found != None:
                        new_nodeid = nodeid_found.group(1)
                        time = float(time_found.group(1))
                        if new_nodeid != last_nodeid:
                            if not start_burst_times.has_key(new_nodeid):
                                start_burst_times[new_nodeid] = []

                            start_burst_times[new_nodeid].append(time)

                            if not stop_burst_times.has_key(last_nodeid):
                                stop_burst_times[last_nodeid] = []

                            stop_burst_times[last_nodeid].append(last_time)
                        
                        last_nodeid = new_nodeid
                        last_time = time
                            
        return (start_burst_times, stop_burst_times)

    def get_sent_pkts_times_at(self, node_id, flow_id, lvl = 'MAC'):
        """Gets sent pkts times"""
        sent_times = []
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
        
            if send_event_found:
                trac_lvl_found = get_trace_lvl.search(line)
                                
                if trac_lvl_found and trac_lvl_found.group(1) == lvl:
                    nodeid_found = get_node_id.search(line)
                    time_found = get_event_time.search(line)
                    flowid_found = get_pktip_flwid.search(line)
                    pktid_found = get_pktip_unqid.search(line)

                    if time_found and nodeid_found and flowid_found and pktid_found:
                        nodeid = nodeid_found.group(1)
                        flowid = flowid_found.group(1)
                        pktid = pktid_found.group(1)
                        time = time_found.group(1)

                        if nodeid == node_id and flowid == flow_id:
                            sent_times.append((pktid,time))
        return sent_times

    def get_recv_pkts_times_at(self, node_id, flow_id, lvl = 'MAC'):
        recv_times = []
        for line in self.input_lines:
            recv_event_found = find_recv_event.search(line)
        
            if recv_event_found:
                trac_lvl_found = get_trace_lvl.search(line)

                if trac_lvl_found and trac_lvl_found.group(1) == lvl:
                    nodeid_found = get_node_id.search(line)
                    time_found = get_event_time.search(line)
                    flowid_found = get_pktip_flwid.search(line)
                    pktid_found = get_pktip_unqid.search(line)
                    
                    if time_found and nodeid_found and flowid_found and pktid_found:
                        nodeid = nodeid_found.group(1)
                        flowid = flowid_found.group(1)
                        pktid = pktid_found.group(1)
                        time = time_found.group(1)
                        
                        if nodeid == node_id and flowid == flow_id:
                            recv_times.append((pktid,time))
        return recv_times

    def get_recv_flow_total_size_at(self, node_id, flow_id, hdr_size, lvl = 'AGT'):
        recv_size = int(0)
        for line in self.input_lines:
            recv_event_found = find_recv_event.search(line)
            
            if recv_event_found:
                trac_lvl_found = get_trace_lvl.search(line)
                
                if trac_lvl_found and trac_lvl_found.group(1) == lvl:
                    nodeid_found = get_node_id.search(line)
                    time_found = get_event_time.search(line)
                    flowid_found = get_pktip_flwid.search(line)
                    pktsize_found = get_pktip_size.search(line)
                    
                    if time_found and nodeid_found and flowid_found and pktsize_found:
                        nodeid = nodeid_found.group(1)
                        flowid = flowid_found.group(1)
                        pktsize = int(pktsize_found.group(1))
                        time = time_found.group(1)

                        if nodeid == node_id and flowid == flow_id:
                            payload = pktsize - hdr_size
                            recv_size = recv_size + payload

        return recv_size

    def get_all_mac_dst(self):
        """
        Returns a list with all mac destination (-Md) in the trace file
        example: print parser.get_all_mac_dst
        """
        sent_mac_dsts = []
        recv_mac_dsts = []
        drop_mac_dsts = []
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)
            
            if send_event_found:
                macdst = get_pkmac_dst.search(line)
                sent_mac_dsts.append(macdst.group(1))
                
            if recv_event_found:
                macdst = get_pkmac_dst.search(line)
                recv_mac_dsts.append(macdst.group(1))

            if drop_event_found:
                macdst = get_pkmac_dst.search(line)
                drop_mac_dsts.append(macdst.group(1))

        return (sent_mac_dsts, recv_mac_dsts, drop_mac_dsts)

