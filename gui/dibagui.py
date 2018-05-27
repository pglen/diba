#!/usr/bin/env python

import os, sys, getopt, signal, uuid
import gobject, gtk, pango, subprocess

import random, time
import newcust, pysql, sutil, treehand, yellow
import custselect

version = 1.0
verbose = False
xstr = ""

# Where things are stored (backups, orgs, macros)
#data_dir = os.path.expanduser("~/.digital_bank")

# The production code will put it somwhere else
dataroot = os.getcwd()

data_dir        = dataroot + "/../data/customers/"
key_dir         = dataroot + "/../data/customers/keys/"
currency_dir    = dataroot + "/../data/currency/"
blockchain_dir  = dataroot + "/../data/blockchain/"
audit_dir       = dataroot + "/../data/audit/"

def showgtk():
    pprint(gtk.__dict__)

def pprint(ddd):        
    for aa in ddd:
        print aa, "\t", ddd[aa]

# ------------------------------------------------------------------------

class MainWin():

    def __init__(self):
    
        self.timerx = 0
        
        self.window = window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        window.set_title("DigiBank Main Screen")
        window.set_position(gtk.WIN_POS_CENTER)
        
        #ic = gtk.Image(); ic.set_from_stock(gtk.STOCK_DIALOG_INFO, gtk.ICON_SIZE_BUTTON)
        #window.set_icon(ic.get_pixbuf())
        
        www, hhh = sutil.get_screen_wh()
        #print "www", www, "hhh", hhh
        #print "xx / yy", sutil.get_screen_xy()
            
        window.set_default_size(13*www/16, 13*hhh/16)
        window.set_flags(gtk.CAN_FOCUS | gtk.SENSITIVE)
         
        window.set_events(gtk.gdk.ALL_EVENTS_MASK )

        '''window.set_events(  gtk.gdk.POINTER_MOTION_MASK |
                            gtk.gdk.POINTER_MOTION_HINT_MASK |
                            gtk.gdk.BUTTON_PRESS_MASK |
                            gtk.gdk.BUTTON_RELEASE_MASK |
                            gtk.gdk.KEY_PRESS_MASK |
                            gtk.gdk.KEY_RELEASE_MASK |
                            gtk.gdk.FOCUS_CHANGE_MASK )'''
         
        window.connect("unmap", self.OnExit)
        window.connect("key-press-event", self.key_press_event)        
        window.connect("button-press-event", self.area_button)        
        
        try:
            window.set_icon_from_file("images/icon.png")
        except:
            pass

        gobject.timeout_add(1000, self.handler_tick)

        #yellow.stickWin(window, "hello", "Want")

        notebook = gtk.Notebook(); self.notebook = notebook
        notebook.popup_enable()
        notebook.set_scrollable(True)

        notebook.add_events(gtk.gdk.ALL_EVENTS_MASK)

        notebook.connect("switch-page", self.note_swpage_cb)
        notebook.connect("focus-in-event", self.note_focus_in)
     
        vbox = gtk.VBox();   vbox2 = gtk.VBox()
        hbox = gtk.HBox();   hbox2 = gtk.HBox()
        
        self.tree = treehand.TreeHand(self.tree_sel_row)
        hbox2.pack_start(self.tree.stree)
        
        self.txt1 = gtk.Label("None")
        hbox2.pack_start(self.txt1)
        
        vbox.pack_start(hbox2)
        
        #lab1 = gtk.Label("");  hbox.pack_start(lab1)
        lab2 = gtk.Label("");  hbox.pack_start(lab2, True)
        
        ib2 = self.imgbutt("images/person.png", " _New Account ", self.new_account, window)
        hbox.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/select.png", " Selec_t Account ", self.sel_account, window)
        hbox.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/search.png", " _Search ", self.search, window)
        hbox.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/icon.png", " Show _Balance ", self.show_one, window)
        hbox.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/transact.png", " _Show Transactions ", self.transact, window)
        hbox.pack_start(ib2, False)
        
        lab2e = gtk.Label("");  hbox.pack_start(lab2e, True)
        
        
        hbox3 = gtk.HBox()
        lab3 = gtk.Label("");  hbox3.pack_start(lab3, True)
        
        ib2 = self.imgbutt("images/icon.png", "  _Hide All  ", self.hide_all, window)
        hbox3.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/icon.png", "  H_ide One  ", self.hide_one, window)
        hbox3.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/icon.png", "  _Delete One   ", self.del_one, window)
        hbox3.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/icon.png", "  Hide _Main  ", self.hide_main, window)
        hbox3.pack_start(ib2, False)
        
        ib2 = self.imgbutt("images/icon.png", "   E_xit  ", self.exit_all, window)
        hbox3.pack_start(ib2, False)
        
        lab4 = gtk.Label("");  hbox3.pack_start(lab4, True)
        self.account = gtk.Label("DigiBank: No account selected");
        attr = pango.AttrList()
        attr.insert(pango.AttrSize(30000, 0, -1))
        attr.insert(pango.AttrForeground(0, 0, 65535, 0, -1))
        self.account.set_attributes(attr)
                                  
        self.activity = gtk.Label("Current activity: Idle ");
        attr2 = pango.AttrList()
        attr2.insert(pango.AttrSize(20000, 0, -1))
        self.activity.set_attributes(attr2)
        
        vbox2.pack_start(gtk.Label(" "), True)
        vbox2.pack_start(self.account, False)
        vbox2.pack_start(hbox, False)
        vbox2.pack_start(hbox3, False)
        vbox2.pack_start(self.activity, False)
        vbox2.pack_start(gtk.Label(" "), True)
        
        self.progress("DIBA: Done init")
            
        notebook.append_page(vbox2)  
        notebook.set_tab_label(vbox2, gtk.Label("  Main  "));
        notebook.append_page(vbox)  
        notebook.set_tab_label(vbox, gtk.Label("  Monitor  "));
        window.add(notebook)
        
    def imgbutt(self, imgfile, txt, func, win):
        hbb = gtk.HBox()
        vbb = gtk.VBox()
        ic = gtk.Image(); 
        ic.set_from_file(imgfile)
        pb = ic.get_pixbuf();
        pb2 = pb.scale_simple(150, 150, gtk.gdk.INTERP_BILINEAR)
        ic2 = gtk.image_new_from_pixbuf(pb2)
        butt1d = gtk.Button(txt)
        butt1d.connect("clicked", func, win)
        vbb.pack_start(gtk.Label(" "))
        vbb.pack_start(ic2, False)
        vbb.pack_start(gtk.Label(" "))
        vbb.pack_start(butt1d, False)
        vbb.pack_start(gtk.Label(" "))
        
        hbb.pack_start(gtk.Label("  "))
        hbb.pack_start(vbb)
        hbb.pack_start(gtk.Label("  "))
        
        return hbb
        
    def exit_all(self, area = None, win = None):
        #print "exit_all"
        self.window.hide()

    def next(self, org):
        print "next", org.head
                    
    def transact(self, area, me):
        pass
        
    def get_one(self, area, me):
        pass
        
    def show_one(self, area, me):
        pass
        
    def  note_focus_in(self, win, act):
        pass
        
    def  note_swpage_cb(self, tabx, page, num):
        pass

    def del_one(self, area, me):
        pass
                             
    def above_one(self, area, me):
        pass
                             
    def hide_one(self, area, me):
        pass
        
    def done_dlg(self, dlg):
        global window2, dibadb
        head = dlg.head.get_text()
        buff = dlg.text.get_buffer()
        ss = buff.get_start_iter(); ee = buff.get_end_iter()
        text = buff.get_text(ss, ee)
        #print  "done_dlg", head, text
        dibadb.put(head, text)
        dibadb.putshow(head, 1)        
        
        found = False 
        '''for aa in yellow.slist.data:
            if aa.head == xstr:
                found = True 
                print "update", head, text
                aa.head = head
                aa.text = text
                aa.window.head = head
                aa.window.text = text
                
                aa.invalidate()
                yellow.usleep(1)
                aa.window.show()'''
                
        if not found:
            '''print "creating", head
            cc = yellow.stickWin(window2, head, text)
            pp = dibadb.getpos(head)        
            if pp:
                cc.window.xx = pp[0]; cc.window.yy = pp[1]   
            aa.window.move(aa.window.xx, aa.window.yy)'''
            pass
            
        self.window.present()
        
    def sel_account(self, area, me):
        print "sel_account"
        res = []
        try:
            res = dibadb.getcustnames()
            print "Showing database info:"
            for aa in res:
                print aa
        except:
            self.progress("Cannot fetch name list.")
            print "Cannot fetch name list.", sys.exc_info()
            pass
            
        selx = custselect.ListCust(self.window, res)
        selx.run()
        print "done list"
        
    def progress(self, text):
        self.activity.set_text(text)
        sutil.usleep(20);
        self.timerx = 5;
        
    def getkeyid(self, fname):
        strx = ""
        arr = ["..\\transport\dibakeyinfo.exe", fname]
        #print arr
        try:
            p3 = subprocess.Popen(arr, stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
            output = p3.communicate()
            #print "My out", output, p3.returncode
            strx = output[0]
            if p3.returncode:
                print "getkey ID failed", output
        except:
            sutil.print_exception("keygen")
        return strx
    
    def unlink_noerr(self, fname):
        try:           
            os.unlink(fname)
        except:
            pass
            
    # Evaluate callback, return string with error. Empty string for OK.
    def callback(self, form):
        global dibadb
        self.arr2 = {}
        for aa in form.arr:
            if type(aa[1])  == gtk.Entry:
                #print "entry", aa[0],  aa[1].get_text()
                self.arr2[aa[0]] = aa[1].get_text()
            elif type(aa[1])  == gtk.TextView:
                buff = aa[1].get_buffer()
                txtx = buff.get_text(buff.get_start_iter(), buff.get_end_iter()) 
                #print "textview", aa[0], txtx
                self.arr2[aa[0]] = txtx
            else:
               self.arr2[aa[0]] = aa[1]
                  
        if self.arr2['cname'] == "":            
            return "Name cannot be empty."
            
        isaddr =  self.arr2['addr1'] != "" and  self.arr2['city'] != "" and \
                     self.arr2['county'] != "" and self.arr2['country'] != ""
        
        if self.arr2['phone'] == "" and self.arr2['email'] == "" and \
            not isaddr:
            return "Must have phone or address or email."
            
        dibadb.put(self.arr2)
        
        return ""
        
    def new_account(self, area, me):
        #print "new_account" 
        serial = uuid.uuid4()
        fname = key_dir + str(serial)
        #fname = sutil.tmpname(data_dir, "cust_key")
        self.progress("Started account generation: " + os.path.basename(fname))
        custform = newcust.NewCust(self.window, self.callback, serial)
        retx = custform.run()
        #custform.destroy()
        #print "after custrun"
        if retx == False:
            self.progress("Cancelled account generation. ")
            return
        
        if fname == "":
            self.progress("Cannot create temporary key file.")
            return 
        
        ret = ""; retcode = 0
        self.unlink_noerr(fname + ".key");  
        self.unlink_noerr(fname + ".pub");
        self.unlink_noerr(fname + ".err");
    
        arr = ["bash", "start", "rxvt -e", 
                         "..\\transport\dibakeygen.exe", "-f", "-w", 
                            "-e", fname + ".err", fname]
        try:
            p2 = subprocess.Popen(arr, stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
            output = p2.communicate()
            '''if p2.returncode:
                print "failed", output'''
        except:
            print "Cannot exceute keygen"
            sutil.print_exception("keygen")
            self.progress("Cannot execute keygen.")
        
        if os.access(fname + ".key", os.R_OK):
            strx = self.getkeyid(fname + ".pub")
            idx = strx.find("'") + 1
            if idx > 1: 
                idx2 = strx.find("'", idx)
                if idx2:
                    strx = strx[idx:idx2]
            self.progress("Key generated. ID = '" + strx + "'")
            self.account.set_text("DIBA Customer: " + self.arr2['cname']);
        
            #sutil.message("New Key Generated.\n\n", self.window)
        else:
            self.progress("Keygen Failed")
            strx = ""
            try:
                strx = open(fname + ".err").read()
            except:
                pass
            sutil.message("New Key Generation failed.\n\n" + strx, self.window)
            
        self.unlink_noerr(fname + ".err");

    def search(self, area, me):
        print "search"
    
    def hide_all(self, area, me):
        #print "hide_all"
        return False 
                         
    def hide_main(self, area, me):
        #print "hide_main"
        me.iconify()
    
    def area_button(self, area, event):
        #print "main butt"
        return False 
    
    def tree_sel_row(self, xtree):
        #print tree
        return False 
    
    def key_press_event(self, area, event):
        #print "main keypress" #, area, event
        return False 
    
    def OnExit(self, aa):
        #print "OnExit"
        # Save data
        gtk.main_quit()
        return False 

    def handler_tick(self):
        if self.timerx > 0:
            self.timerx -= 1
        if self.timerx == 1:
            self.activity.set_text("Diba GUI Idle")
        
        gobject.timeout_add(1000, self.handler_tick)
    
                                              
def key_press_event(win, aa):
    print "key_press_event", win, aa
            
def help():

    print 
    print "dibagui version: ", version
    print 
    print "Usage: " + os.path.basename(sys.argv[0]) + " [options] [[filename] ... [filenameN]]"
    print 
    print "Options:"
    print "            -d level  - Debug level 1-10. (Limited implementation)"
    print "            -v        - Verbose (to stdout and log)"
    print "            -c        - Dump config"
    print "            -s        - Show database"
    print "            -r        - Remove database (test oly)"
    print "            -h        - Help"
    print

def softmkdir(dirx):
    try:
        if not os.path.isdir(dirx):
            os.mkdir(dirx)
    except:
        print "Cannot make directory:",  dirx
        raise
        
# ------------------------------------------------------------------------
# Start of program:

if __name__ == '__main__':

    global dibadb, pg_debug
    
    verbose = False 
    show_config = False; show_timing = False;  
    show_database = False; remove_database = False
    pg_debug = 0
    
    #  Preconditions
    try:
        softmkdir(data_dir)
        softmkdir(key_dir)
        softmkdir(currency_dir)
        softmkdir(blockchain_dir)
        softmkdir(audit_dir)
    except: 
        print "Cannot make dir", sys.exc_info()
        sys.exit(2)
        
    # Let the user know it needs fixin'
    if not os.path.isdir(data_dir):
        print "Cannot access data dir:", data_dir
        sys.exit(3)
    if not os.access(data_dir, os.W_OK):
        print "Cannot write to data dir:", data_dir
        sys.exit(4)

    dibadb = pysql.dibasql(data_dir + "/data.mysql")
    
    opts = []; args = []
    try:
        opts, args = getopt.getopt(sys.argv[1:], "d:avchsr")
    except getopt.GetoptError, err:
        print "Invalid option(s) on command line:", err
        sys.exit(1)

    #print "opts", opts, "args", args
    
    for aa in opts:
        if aa[0] == "-d":
            try:
                pg_debug = int(aa[1])
                if pg_debug > 10: pg_debug = 10
                if pg_debug < 0: pg_debug = 0
                if verbose:
                    print "Debug level ", pg_debug
            except:
                print "Bad argument on option -d:", sys.exc_info() 
                sys.exit(2)
                
        if aa[0] == "-h": help();  exit(1)
        if aa[0] == "-v": verbose = True            
        if aa[0] == "-g": showgtk(); exit(1);
        if aa[0] == "-c": show_config = True            
        if aa[0] == "-t": show_timing = True
        if aa[0] == "-s": show_database = True
        if aa[0] == "-r": remove_database = True

    if verbose:
        print "dibagui running on", "'" + os.name + "'", \
            "GTK", gtk.gtk_version, "PyGtk", gtk.pygtk_version

    if show_database:
        db, dd = dibadb.getall()
        print "Showing database info:"
        for aa in range(len(db)):
            for bb in range(len(dd)):
                print dd[bb][0], "= '" + str(db[aa][bb]) + "',\t", 
            print; print
        
    # For testing
    if remove_database:
        print "This is for testing / development. Are you sure? (yes/no)"
        aa = sys.stdin.readline()
        if aa[:3] == "yes":
            print "Removing data ... ",
            rr = dibadb.rmall()
            print rr
        else:
            print "Not removed, Type the word 'yes' for data removal."
        sys.exit(0)
        
    #if(show_config):
    #    print dibadb.getall()
        
    mainwin = MainWin()
    mainwin.window.show_all()    
    gtk.main()

