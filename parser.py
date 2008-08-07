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

find_send_event = re.compile("^s")
find_recv_event = re.compile("^r")
find_drop_event = re.compile("^d")
find_fwrd_event = re.compile("^t")

get_event_time = re.compile("-t ([0-9.]*)")
get_node_id = re.compile("-Ni (\d)")
get_node_pos = re.compile("-Nx (\d) -Ny (\d) -Nz (\d)")
get_node_nrg = re.compile("-Ne (-[0-9.]*)")
get_trace_lvl = re.compile("-Nl ([A-Z]+)")
get_event_rsn = re.compile("-Nw ([A-Z]+)")
get_pktip_src = re.compile("-Is ([0-9]+).([0-9]+)")
get_pktip_dst = re.compile("-Id ([0-9]+).([0-9]+)")
get_pktip_type = re.compile("-It ([a-z]+)")
get_pktip_size = re.compile("-Il ([0-9]+)")
get_pktip_flwid = re.compile("-If ([0-9]+)")
get_pktip_unqid = re.compile("-Ii ([0-9]+)")
get_pktip_ttl = re.compile("-Iv ([0-9]+)")
get_nxhop_sid = re.compile("-Hs ([0-9]+)")
get_nxhop_did = re.compile("-Hd ([0-9]+)")
get_pkmac_dur = re.compile("-Ma ([0-9]+)")
get_pkmac_dst = re.compile("-Md (\w+)")
get_pkmac_src = re.compile("-Ms (\w+)")
get_pkmac_type = re.compile("-Mt ([0-9]+)")
get_pkapp_sqn = re.compile("-Pi ([0-9]+)")
get_pkapp_fwd = re.compile("-Pf ([0-9]+)")
get_pkapp_opt = re.compile("-Po ([0-9]+)")


class NS2NewTraceParser:
    """
    This class parse the new trace parser
    Open a file and pass it to the constructor
    trace_file = open('trace_file.tr','r')
    parser = NSNewTraceParser(trace_file)
    then you could use methods
    """
    def __init__(self, input_file):
        self.input_lines = input_file.readlines()

    def get_pkg_iptypes(self):
        """
        Returns a list of package ip types (-It) present in the trace file
        example: types = parser.get_pkg_iptypes()
        """
        known_types = []
        for line in self.input_lines:
            type = get_pktip_type.search(line)
            if type != None:
                new_type = type.group(1)
                if new_type not in known_types:
                    known_types.append(new_type)
        return known_types

    def get_trace_of(self, unique_id):
        """
        Return a list of trace lines for the package with unique_id
        example: print parser.get_trace_of('1')
        """
        pkg_trace = []
        for line in self.input_lines:        
            uniqid = get_pktip_unqid.search(line)
            if uniqid != None and uniqid.group(1) == unique_id:
                pkg_trace.append(line)
        return pkg_trace
                
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

    def count_recv_pkg_at_node(self, node_id):
        """
        Returns the number of packages received at the node node_id
        example: num_recv_pkgs = parser.count_recv_pkg_at_node('1')
        """
        recv_pkg = 0
        for line in self.input_lines:
            recv_event_found = find_recv_event.search(line)
            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                nodeid = get_node_id.search(line)
                if nodeid != None and tracelvl != None:
                    if nodeid.group(1) == node_id and tracelvl.group(1) == "MAC":
                        recv_pkg = recv_pkg + 1
        return recv_pkg

    def get_pkgs_at_macdst(self, mac_dest):
        """
        Returns unique_id of packages with mac destination == mac_dest
        example: parser.get_pkgs_at_macdst('fffff')
        """
        sent_pkg = []
        recv_pkg = []
        drop_pkg = []
        
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
                                sent_pkg.append(seqnum.group(1))
                
            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    macdst = get_pkmac_dst.search(line)
                    if macdst.group(1) == mac_dest:
                        seqnum = get_pktip_unqid.search(line)
                        if seqnum != None:
                            if seqnum.group(1) != None:
                                recv_pkg.append(seqnum.group(1))

            if drop_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    macdst = get_pkmac_dst.search(line)
                    if macdst.group(1) == mac_dest:
                        seqnum = get_pktip_unqid.search(line)
                        if seqnum != None:
                            if seqnum.group(1) != None:
                                drop_pkg.append(seqnum.group(1))

        return (sent_pkg, recv_pkg, drop_pkg)
                        
    def get_pkgs_at_lvl(self, lvl):
        """
        Returns a tuple of three lists of sent, received, dropped packets at level lvl ('MAC','AGT','RTR')
        example: (sent_pkg, recv_pkg, drop_pkg) = parser.get_pkgs_at_lvl('MAC')
        """
        
        sent_packets = []
        recv_packets = []
        drop_packets = []
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)
            
            if send_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == lvl:
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum != None:
                        if seqnum.group(1) != None:
                            sent_packets.append(seqnum.group(1))
                            continue
                            
            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == lvl:
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum != None:
                        if seqnum.group(1) != None:
                            recv_packets.append(seqnum.group(1))
                            continue

            if drop_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == lvl:
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum != None:
                        if seqnum.group(1) != None:
                            drop_packets.append(seqnum.group(1))
                            continue

        return (sent_packets, recv_packets, drop_packets)

    def get_pkgs_flowid(self, flowid, lvl = 'MAC'):
        """
        Returns a tuple of three lists of sent, received, dropped packets with flow id = flowid
        and at level lvl ('MAC','AGT','RTR') default lvl is 'MAC'
        example: (sent_pkg, recv_pkg, drop_pkg) = parser.get_pkgs_flowid('MAC')
        """
        sent_packets = []
        recv_packets = []
        drop_packets = []
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)            

            if send_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == lvl:
                    flwid = get_pktip_flwid.search(line)
                    if flwid != None:
                        if flwid.group(1) == flowid:
                            seqnum = get_pktip_unqid.search(line)
                            if seqnum != None:
                                if seqnum.group(1) != None:
                                    sent_packets.append(seqnum.group(1))

            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == lvl:
                    flwid = get_pktip_flwid.search(line)
                    if flwid != None:
                        if flwid.group(1) == flowid:
                            seqnum = get_pktip_unqid.search(line)
                            if seqnum != None:
                                if seqnum.group(1) != None:
                                    recv_packets.append(seqnum.group(1))

            if drop_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == lvl:
                    flwid = get_pktip_flwid.search(line)
                    if flwid != None:
                        if flwid.group(1) == flowid:
                            seqnum = get_pktip_unqid.search(line)
                            if seqnum != None:
                                if seqnum.group(1) != None:
                                    drop_packets.append(seqnum.group(1))

        return (sent_packets, recv_packets, drop_packets)

    def get_trace_maconly_pkgs(self):
        """
        Returns a tuple of three lists of trace lines of sent, received, dropped MAC level packages
        example: lines = parser.get_trace_maconly_pkgs()
        """
        
        sent_macpkg = []
        recv_macpkg = []
        drop_macpkg = []
        
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            drop_event_found = find_drop_event.search(line)            

            if send_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum == None:
                        sent_macpkg.append(line)

            if recv_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum == None:
                        recv_macpkg.append(line)

            if drop_event_found != None:
                tracelvl = get_trace_lvl.search(line)
                if tracelvl != None and tracelvl.group(1) == "MAC":
                    seqnum = get_pktip_unqid.search(line)
                    if seqnum == None:
                        drop_macpkg.append(line)

        return (sent_macpkg, recv_macpkg, drop_macpkg)

    
    def get_sent_bursts_per_flow(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times per sent flowid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_flowid = str()
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

                            if not stop_burst_times.has_key(new_flowid):
                                stop_burst_times[new_flowid] = []

                            stop_burst_times[new_flowid].append(last_time)

                            last_flowid = new_flowid
                            last_time = time
                            
        return (start_burst_times, stop_burst_times)

    def get_sent_bursts_per_node(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times of pkg sent per nodeid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_nodeid = str()
        last_time = float()
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
                        time = float(time_found.group(1))
                        if new_nodeid != last_nodeid:
                            if not start_burst_times.has_key(new_nodeid):
                                start_burst_times[new_nodeid] = []

                            start_burst_times[new_nodeid].append(time)

                            if not stop_burst_times.has_key(new_nodeid):
                                stop_burst_times[new_nodeid] = []

                            stop_burst_times[new_nodeid].append(last_time)

                            last_nodeid = new_nodeid
                            last_time = time
                            
        return (start_burst_times, stop_burst_times)

    def get_recv_bursts_per_flow(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times per received flowid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_flowid = str()
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

                            if not stop_burst_times.has_key(new_flowid):
                                stop_burst_times[new_flowid] = []

                            stop_burst_times[new_flowid].append(last_time)

                            last_flowid = new_flowid
                            last_time = time
                            
        return (start_burst_times, stop_burst_times)

    def get_recv_bursts_per_node(self, lvl = 'MAC'):
        """
        Returns a tuple of two dictionaries mapping start and stop times of pkg recv per nodeid.
        It is possibile to select trace level (default is 'MAC')
        example: (start_times, stop_times) = parser.get_sent_bursts_per_flow()
        """
        last_nodeid = str()
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

                            if not stop_burst_times.has_key(new_nodeid):
                                stop_burst_times[new_nodeid] = []

                            stop_burst_times[new_nodeid].append(last_time)

                            last_nodeid = new_nodeid
                            last_time = time
                            
        return (start_burst_times, stop_burst_times)
