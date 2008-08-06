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


class Parser:
    def __init__(self, input_file):
        self.input_lines = input_file.readlines()

    def get_pkg_types(self):
        known_types = []
        for line in self.input_lines:
            type = get_pktip_type.search(line)
            if type != None:
                new_type = type.group(1)
                if new_type not in known_types:
                    known_types.append(new_type)
        return known_types

    def get_trace_of(self, unique_id):
        pkg_trace = []
        for line in self.input_lines:        
            uniqid = get_pktip_unqid.search(line)
            if uniqid != None and uniqid.group(1) == unique_id:
                pkg_trace.append(line)
        return pkg_trace
                
    def print_mac_dst(self):
        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)
            if send_event_found:
                macdst = get_pkmac_dst.search(line)
                print macdst.group(1)
                
            if recv_event_found:
                macdst = get_pkmac_dst.search(line)
                print macdst.group(1)

    def count_recv_pkg_at_node(self, node_id):
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
        sent_packets = []
        recv_packets = []

        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)

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

        return (sent_packets, recv_packets)

    def get_pkgs_flowid(self, flowid, lvl = 'MAC'):
        sent_packets = []
        recv_packets = []

        for line in self.input_lines:
            send_event_found = find_send_event.search(line)
            recv_event_found = find_recv_event.search(line)

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
                                    continue

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
                                    continue

        return (sent_packets, recv_packets)

    def get_trace_maconly_pkgs(self):
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
