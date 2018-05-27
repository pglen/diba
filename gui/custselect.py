#!/usr/bin/env python

'''Tree View/List Store

The GtkListStore is used to store data in list form, to be used
later on by a GtkTreeView to display it. This demo builds a
simple GtkListStore and displays it. See the Stock Browser
demo for a more advanced example.'''

import pygtk
pygtk.require('2.0')
import gobject, gtk, sutil

(
    COLUMN_FIXED,
    COLUMN_NUMBER,
    COLUMN_SEVERITY,
    COLUMN_DESCRIPTION
) = range(4)

'''data = \
((False, 60482, 'Normal', 'scrollable notebooks and hidden tabs'),
 (False, 60620, 'Critical',
  'gdk_window_clear_area(gdkwindow-win32.c) is not thread-safe'),
 (False, 50214, 'Major', 'Xft support does not clean up correctly'),
 (True,  52877, 'Major', 'GtkFileSelection needs a refresh method. '),
 (False, 56070, 'Normal', "Can't click button after setting in sensitive"),
 (True,  56355, 'Normal', 'GtkLabel - Not all changes propagate correctly'),
 (False, 50055, 'Normal', 'Rework width/height computations for TreeView'),
 (False, 58278, 'Normal', "gtk_dialog_set_response_sensitive() doesn't work"),
 (False, 55767, 'Normal', 'Getters for all setters'),
 (False, 56925, 'Normal', 'Gtkcalender size'),
 (False, 56221, 'Normal', 'Selectable label needs right-click copy menu'),
 (True,  50939, 'Normal', 'Add shift clicking to GtkTextView'),
 (False, 6112,  'Enhancement', 'netscape-like collapsable toolbars'),
 (False, 1,     'Normal', 'First bug :=)'))'''

class ListCust(gtk.Window):

    def __init__(self, parent, data):
    
        # Create window, etc
        self.data = data
        gtk.Window.__init__(self)
        try:
            self.set_screen(parent.get_screen())
        except AttributeError:
            self.connect('destroy', lambda *w: gtk.main_quit())
        
        self.set_title("Diba Customer List")
        
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_position(gtk.WIN_POS_CENTER)
        self.ok = False
        
        #self.set_border_width(8)
        www, hhh = sutil.get_screen_wh()
        self.set_default_size(2*www/4, 2*hhh/4)
        #self.set_default_size(400, 300)

        vbox = gtk.VBox(False, 8)
        #vbox = self.get_content_area()
        #print vbox
        #self.add_content_widget(vbox, 1)
        self.add(vbox)

        label = gtk.Label('Select DIBA Customer')
        vbox.pack_start(label, False, False)

        self.connect("key-press-event", self.key_press_event)        
        
        hbox = gtk.HBox()
        vbox.pack_start(hbox, False)
        hbox.pack_start(gtk.Label("    "), False)
        
        for aa in range(ord("Z") - ord("A") + 1):
            hbox.pack_start(gtk.Button(" " + str(chr(ord("A") + aa)+ " " )), True)
            
        hbox.pack_start(gtk.Label("    "), False)
        
        sw = gtk.ScrolledWindow()
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        vbox.pack_start(sw)

        # create tree model
        model = self.__create_model()

        # create tree view
        treeview = gtk.TreeView(model)
        treeview.set_rules_hint(True)
        treeview.set_search_column(COLUMN_DESCRIPTION)

        sw.add(treeview)

        # add columns to the tree view
        self.__add_columns(treeview)
        self.show_all()
        
    def __create_model(self):
        lstore = gtk.ListStore(
            #gobject.TYPE_BOOLEAN,
            #gobject.TYPE_UINT,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_STRING)

        for item in self.data:
            iter = lstore.append()
            lstore.set(iter,
                COLUMN_FIXED, str(item[COLUMN_FIXED]),
                COLUMN_NUMBER, item[COLUMN_NUMBER],
                COLUMN_SEVERITY, item[COLUMN_SEVERITY],
                COLUMN_DESCRIPTION, item[COLUMN_DESCRIPTION])
        return lstore

    def fixed_toggled(self, cell, path, model):
        # get toggled iter
        iter = model.get_iter((int(path),))
        fixed = model.get_value(iter, COLUMN_FIXED)

        # do something with the value
        fixed = not fixed

        # set new value
        model.set(iter, COLUMN_FIXED, fixed)

    def __add_columns(self, treeview):
        model = treeview.get_model()

        # column for fixed toggles
        #renderer = gtk.CellRendererToggle()
        #renderer.connect('toggled', self.fixed_toggled, model)
        #column = gtk.TreeViewColumn('Primary', renderer, active=COLUMN_FIXED)
        column = gtk.TreeViewColumn('Primary', gtk.CellRendererText(), text=COLUMN_FIXED)

        # set this column to a fixed sizing(of 50 pixels)
        #column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        #column.set_fixed_width(50)

        treeview.append_column(column)

        # column for bug numbers
        column = gtk.TreeViewColumn('Customer Name', gtk.CellRendererText(),
                                    text=COLUMN_NUMBER)
        column.set_sort_column_id(COLUMN_NUMBER)
        treeview.append_column(column)

        # columns for severities
        column = gtk.TreeViewColumn('Customer ID', gtk.CellRendererText(),
                                    text=COLUMN_SEVERITY)
        column.set_sort_column_id(COLUMN_SEVERITY)
        treeview.append_column(column)

        # column for description
        column = gtk.TreeViewColumn('Description', gtk.CellRendererText(),
                                     text=COLUMN_DESCRIPTION)
        column.set_sort_column_id(COLUMN_DESCRIPTION)
        treeview.append_column(column)

    def key_press_event(self, win, event):
        if event.keyval == gtk.keysyms.Escape:
            self.destroy()
        #print "keystate", event.state
        if event.keyval == gtk.keysyms.x and event.state & gtk.gdk.MOD1_MASK:
            self.destroy()
    
    # Run as modal dialog until destroyed
    def run(self):
        self.show_all()
        while True:
            ev = gtk.gdk.event_peek()
            #print ev
            if ev:
                if ev.type == gtk.gdk.DELETE:
                    break
                if ev.type == gtk.gdk.UNMAP:
                    break
            gtk.main_iteration_do()
        self.destroy()
        return self.ok
    
def main():
    ListCust()
    gtk.main()

if __name__ == '__main__':
    main()




