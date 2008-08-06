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
        mac_dsts = []
        line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            if send_event_found:
                macdst = get_pkmac_dst.search(line)
                mac_dsts.append(macdst.group(1))
                
            if recv_event_found:
                macdst = get_pkmac_dst.search(line)
                mac_dsts.append(macdst.group(1))

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
