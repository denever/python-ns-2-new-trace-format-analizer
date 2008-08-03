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
get_pktip_type = re.compile("-It ([ar+)")
get_pktip_size = re.compile("-Il ([0-9]+)")
get_pktip_flwid = re.compile("-If ([0-9]+)")
get_pktip_unqid = re.compile("-Ii ([0-9]+)")
get_pktip_ttl = re.compile("-Iv ([0-9]+)")
get_nxhop_sid = re.compile("-Hs ([0-9]+)")
get_nxhop_did = re.compile("-Hd ([0-9]+)")
get_pkmac_dur = re.compile("-Ma ([0-9]+)")
get_pkmac_src = re.compile("-Md (\w+)")
get_pkmac_dst = re.compile("-Ms (\w+)")
get_pkmac_type = re.compile("-Mt ([0-9]+)")
get_pkapp_sqn = re.compile("-Pi ([0-9]+)")
get_pkapp_fwd = re.compile("-Pf ([0-9]+)")
get_pkapp_opt = re.compile("-Po ([0-9]+)")

if len(sys.argv) == 2:
    input_file = open(sys.argv[1], 'r') # apre il file in read
else:
    print "usage tracana.py input_file output_file"
    sys.exit(1)

for line in input_file.readlines():
    send_event_found = find_send_event.search(line)
    recv_event_found = find_recv_event.search(line)
    drop_event_found = find_drop_event.search(line)
    fwrd_event_found = find_fwrd_event.search(line)
    
    if send_event_found:
        time = get_time.search(line)
        print time.group(1)


