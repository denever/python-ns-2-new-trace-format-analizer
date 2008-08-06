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
from parser import NS2NewTraceParser

def save_lines_in(filename, lines):
    lost_pkg_tr = open(filename, 'w')
    for line in lines:
        lost_pkg_tr.write(line)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        input_file = open(sys.argv[1], 'r') # apre il file in read
    else:
        print "usage tracana.py input_file"
        sys.exit(1)
    
    parser = Parser(input_file)

    for flowid  in range(1,12):
        print "Checking flow: ", flowid, "..."
        (sent, recv) = parser.get_pkgs_flowid(str(flowid))

        if len(sent) != len(recv):
            print "Flow " + str(flowid) + " has lost pkgs!"
            print "Recv pkgs: ", len(sent)
            print "Sent pkgs: ", len(recv)
            print "Finding unique_id of lost pkgs..."

            lost_pkgs = []
            for sent_pkg in sent:
                if sent_pkg not in recv:
                    print 'Pkg ' + sent_pkg + ' was lost'
                    lost_pkgs.append(sent_pkg)

            print "Retriving trace for lost pkgs..."
            for lost_pkg in lost_pkgs:
                filename = 'lost_pkg_' + lost_pkg + '.tr'
                print 'Saving trace of lost pkg ' + lost_pkg + ' in...' + filename

                lines = parser.get_trace_of(lost_pkg)
                save_lines_in(filename, lines)
        else:
            print "All pkgs of flow " + str(flowid) + " were received"
            
        print "Checking sequence for pkgs of flow ", flowid, "..."
        tmp = int(-1)
        for recv_pkg in recv:
            if not int(recv_pkg) > tmp:
                print 'Wrong sequence at ', tmp, recv_pkg
            tmp = int(recv_pkg)
        print "Pkgs of flow " + str(flowid) + " were received in the correct sequence"

    (sent_trace, foo, bar) = parser.get_trace_maconly_pkgs()
    save_lines_in('unknown_macpkgs.txt',sent_trace)
