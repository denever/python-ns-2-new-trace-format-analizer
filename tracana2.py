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
    
    parser = NS2NewTraceParser(input_file)

    (start_bursts, stop_bursts) = parser.get_sent_bursts_per_node('MAC')

    for nodeid in start_bursts.keys():
        if not nodeid == '0':
            for i in range(len(start_bursts[nodeid])):
                duration = float(stop_bursts[nodeid][i]) - float(start_bursts[nodeid][i])
                print "Node id:", nodeid, "Start:", start_bursts[nodeid][i], "duration:", round(duration, 6)  
