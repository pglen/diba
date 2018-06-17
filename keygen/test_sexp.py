#!/usr/bin/python

#from sexpdata import loads, dumps

import sys
#import sexpdata 
import base64
#import sexpParser

import pytest

from pygcrypt.gctypes.sexpression import SExpression
from pygcrypt.gctypes.mpi import MPIopaque, MPIint

if __name__ == '__main__':

    fp = open(sys.argv[1])
    #fp = open("bb.query")
    strx = fp.read()
    #print (strx)
    
    bb = ""
    
    for aa in str.split(strx, "\n"):
        if not "DIGIBANK RSA" in aa:
            #print ("line:", aa)
            bb += aa        
    
    cc = base64.b64decode(bb) #.decode("ascii")
    #print(cc)
    
    s_expr = SExpression(cc)
    
    print (s_expr.dump())
    
    slen = len(s_expr)
    print("len =", slen )
    kkk = s_expr.cdr.keys()
    
    for aaa in kkk:
        print ("Key:", aaa, )
        vvv = s_expr[aaa].getstring(0)
        if vvv:
            print("Val:", vvv)
        else:
            vvv = s_expr[aaa].getdata(0)
            if vvv:
                print("Data:", vvv)
            
        if len(s_expr[aaa]) > 1:
            kkkk = s_expr[aaa]
            for bbb in kkkk.keys():
                vvvv = kkkk[bbb].getdata(0)
                print ("        SubKey:", bbb, "val", vvvv)
        
    '''
    for aa in s_expr:
        bb = aa.keys()
        for cc in bb:
            try:
                print ("key:",cc) 
            except:
                print ("none")
            try:
                print ("val:", aa.getvalue(cc))
            except:
                print ("no int")
            try:
                print ("val:", aa.getstring(cc))
            except:
                print ("no str")
    '''            
    #print (s_expr.keys())
    


        
        




