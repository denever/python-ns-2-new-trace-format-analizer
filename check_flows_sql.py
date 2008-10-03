#! /usr/bin/env python
# -*- Python -*-
###########################################################################
#                       Trace Analizer Example                            #
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

import sys
from NS2NewTraceSql import NS2NewTraceSql

def save_lines_in(filename, lines):
    lost_pkt_tr = open(filename, 'w')
    for line in lines:
        lost_pkt_tr.write(str(line)+'\n')

if __name__ == '__main__':
    if len(sys.argv) == 2:
        db = sys.argv[1]
        input_file = None
    elif len(sys.argv) == 3:
        db = sys.argv[1]
        input_file = sys.argv[2]
    else:
        print "usage: check_flows_sql.py file.pta [file.tr]"
        
    parser = NS2NewTraceSql(db, input_file)

    for flowid  in range(0,12):
        print "Checking flow: ", flowid, "..."
        (sent, recv, drop) = parser.get_pkts_flowid(flowid)
#        print len(sent), len(recv)
        if len(sent) != len(recv):
            print "Flow " + str(flowid) + " has lost pkts!"
            print "Recv pkts: ", len(sent)
            print "Sent pkts: ", len(recv)
            print "Finding unique_id of lost pkts..."

            lost_pkts = []
            for sent_pkt in sent:
                if sent_pkt not in recv:
                    print 'Pkt %d was lost' % sent_pkt
                    lost_pkts.append(sent_pkt)

            print "Retriving trace for lost pkts..."
            for lost_pkt in lost_pkts:
                filename = 'lost_pkt_%d.tr' % lost_pkt
                print 'Saving trace of lost pkt %d' % lost_pkt, 'in...' + filename

                lines = parser.get_trace_of(lost_pkt)
                save_lines_in(filename, lines)
        else:
            print "All pkts of flow " + str(flowid) + " were received"
            
        print "Checking sequence for pkts of flow ", flowid, "..."
        tmp = int(-1)
        for recv_pkt in recv:
            if not int(recv_pkt) > tmp:
                print 'Wrong sequence at ', tmp, recv_pkt
            tmp = int(recv_pkt)
        print "Pkts of flow " + str(flowid) + " were received in the correct sequence"

#    (sent_trace, foo, bar) = parser.get_trace_maconly_pkts()
#    save_lines_in('unknown_macpkts.txt',sent_trace)
