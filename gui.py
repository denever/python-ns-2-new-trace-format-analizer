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
from parser import NS2NewTraceParser

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

    def on_mnuitm_open_activate(self, widget):
        self.wtree.get_widget('dlg_openfile').show()        

    def on_mnuitm_save_activate(self, widget):
        self.wtree.get_widget('dlg_savefile').show()        
        
    def on_btn_open_clicked(self, widget):
        filename = self.wtree.get_widget('dlg_openfile').get_filename()
        trace_file = open(filename,'r')
        self.parser = NS2NewTraceParser(trace_file)
        
        tvw_nodes = self.wtree.get_widget('tvw_nodes')
        tvc_nodes = gtk.TreeViewColumn('Id')
        cell = gtk.CellRendererText()
        tvc_nodes.pack_start(cell)
        tvc_nodes.set_attributes(cell, text=0)
        tvw_nodes.append_column(tvc_nodes)
        node_list = gtk.ListStore(str)
        tvw_nodes.set_model(node_list)

        for node_id in self.parser.get_nodes():
            node_list.append([node_id])

        tvw_flows = self.wtree.get_widget('tvw_flows')
        tvc_flows = gtk.TreeViewColumn('Id')
        cell = gtk.CellRendererText()
        tvc_flows.pack_start(cell)
        tvc_flows.set_attributes(cell, text=0)
        tvw_flows.append_column(tvc_flows)
        flow_list = gtk.ListStore(str)
        tvw_flows.set_model(flow_list)

        for flow_id in self.parser.get_flows():
            flow_list.append([flow_id])
            
        self.wtree.get_widget('dlg_openfile').hide()
        self.wtree.get_widget('mnuitm_stats').show()
        
    def on_btn_open_cancel_clicked(self, widget):
        print widget

    def on_btn_save_cancel_clicked(self, widget):
        self.wtree.get_widget('dlg_savefile').hide()
        
    def on_mnuitm_exit_activate(self, widget):
        gtk.main_quit()


if __name__ == "__main__":
    gui = Gui()
    main()


