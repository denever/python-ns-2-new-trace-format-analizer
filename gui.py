#! /usr/bin/env python
# -*- Python -*-
###########################################################################

#                        --------------------                             #

#  copyright            : Giuseppe "denever" Martino                      #
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
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,             #
#  MA 02110-1301 USA                                                      #
#                                                                         #
###########################################################################

import pygtk

pygtk.require('2.0')

import gtk
#import gobject

from gtk import *
from gtk import glade
from NS2NewTraceParser import NS2NewTraceParser

gdk.threads_init()

class Gui:
    def __init__(self):
        self.parser = ''
        self.wtree = glade.XML('glade/traceanalyser.glade')
        self.wtree.get_widget('win_traceanalyser').connect("destroy", main_quit)
    	self.wtree.get_widget('win_traceanalyser').show()        
 	dict = {}
	for key in dir(self.__class__):
	    dict[key] = getattr(self, key)
	self.wtree.signal_autoconnect(dict)

        self.tvw_nodes = self.wtree.get_widget('tvw_nodes')

        tvc_nodes = gtk.TreeViewColumn('Id')
        cell = gtk.CellRendererText()
        tvc_nodes.pack_start(cell)
        tvc_nodes.set_attributes(cell, text=0)
        self.tvw_nodes.append_column(tvc_nodes)
        self.node_list = gtk.ListStore(str)
        self.tvw_nodes.set_model(self.node_list)
        
        self.tvw_flows = self.wtree.get_widget('tvw_flows')
        
        tvc_flowid = gtk.TreeViewColumn('FlowId')
        tvc_src = gtk.TreeViewColumn('Source')
        tvc_dst = gtk.TreeViewColumn('Destination')
        tvc_type = gtk.TreeViewColumn('Type')

        cel_flowid = gtk.CellRendererText()
        cel_src = gtk.CellRendererText()
        cel_dst = gtk.CellRendererText()
        cel_type = gtk.CellRendererText()

        tvc_flowid.pack_start(cel_flowid)
        tvc_src.pack_start(cel_src)
        tvc_dst.pack_start(cel_dst)
        tvc_type.pack_start(cel_type)
        
        tvc_flowid.set_attributes(cel_flowid, text=0)
        tvc_src.set_attributes(cel_src, text=1)
        tvc_dst.set_attributes(cel_dst, text=2)
        tvc_type.set_attributes(cel_type, text=3)
        
        self.tvw_flows.append_column(tvc_flowid)
        self.tvw_flows.append_column(tvc_src)
        self.tvw_flows.append_column(tvc_dst)
        self.tvw_flows.append_column(tvc_type)
        
        self.flow_list = gtk.ListStore(str,str,str,str)
        self.tvw_flows.set_model(self.flow_list)

    def on_mnuitm_open_activate(self, widget):
        self.wtree.get_widget('dlg_openfile').show()        

    def on_mnuitm_save_activate(self, widget):
        self.wtree.get_widget('dlg_savefile').show()        
        
    def on_btn_open_clicked(self, widget):
        self.wtree.get_widget('dlg_openfile').hide()
        filename = self.wtree.get_widget('dlg_openfile').get_filename()
        trace_file = open(filename,'r')
        self.parser = NS2NewTraceParser(trace_file)
        
        for node_id in self.parser.get_nodes():
            self.node_list.append([node_id])

        flow_ids = self.parser.get_flows()
        flow_ids.sort()
        flow_src_dst = self.parser.get_src_dst_per_flow()
        flow_types = self.parser.get_flow_types()
        
        for flow_id in flow_ids:
            (src,dst) = flow_src_dst[flow_id]
            flow_type = flow_types[flow_id]
            row = flow_id,src,dst,flow_type
            self.flow_list.append(row)

        self.wtree.get_widget('mnuitm_stats').show()
        
    def on_btn_open_cancel_clicked(self, widget):
        self.wtree.get_widget('dlg_openfile').hide()

    def on_btn_save_cancel_clicked(self, widget):
        self.wtree.get_widget('dlg_savefile').hide()
        
    def on_mnuitm_exit_activate(self, widget):
        gtk.main_quit()

if __name__ == "__main__":
    gui = Gui()
    main()
