
import idaapi
import idautils
import idc
import ida_funcs
import idc
import base64

idaapi.auto_wait()


signature_data= eval(base64.b64decode(idc.ARGV[1]))


print("[AutoResolvIDATScripts] : save_data.py - start")    

def get_seg(segname):
        for s in idautils.Segments():
            seg = idaapi.getseg(s)
            name = idc.get_segm_name(s)
            if name == segname:
                start = seg.start_ea
                end = seg.end_ea
                return start, end
        
        return None,None
        
def process_function(funs_, s,e):
    external = {}
    funs = idautils.Functions(start = s, end=e)
    for ea in funs:
        px = ida_funcs.get_func_name(ea)
        flags = idc.get_func_flags(ea)
        
        if (flags & 0x80): #all external functions are wrapper -> jump OFFSET, so flags ISJUMP should be 1
            to_add = px.replace(".","") #remove prefix . from function
            if to_add in funs_:
                external[to_add] = ea
        
    return external
    

def applyNewSignature(fun, ea, sig):
    xrefs= idautils.XrefsTo(ea)
    ret = idc.SetType(ea, sig)
    if ret is None:
        print(f"[AutoResolvIDATScripts] SetType has failed for : {fun} at {hex(ea)}")
        return -1
    
    for xref in xrefs:
        if xref.type in {3, 19, idaapi.fl_CF, idaapi.fl_CN}:
            applyNewSignature(fun, xref.frm, sig)
            
        elif xref.type == 21: #special case
            func_name = ida_funcs.get_func_name(xref.frm).replace(".","")
            if func_name == fun:
                applyNewSignature(fun, xref.frm, sig)
    
    
     

def applyComment(fun, ea, lib):
    xrefs= idautils.XrefsTo(ea)
    idc.set_cmt(ea, lib, 1)

    
    for xref in xrefs:
        if xref.type in {3, 19, idaapi.fl_CF, idaapi.fl_CN}:
            applyComment(fun, xref.frm, lib)
            
        elif xref.type == 21: #special case
            func_name = ida_funcs.get_func_name(xref.frm).replace(".","")
            if func_name == fun:
                applyComment(fun, xref.frm, lib)
  

s, e = get_seg(".plt.sec")

for lib in signature_data.keys():
    exported_signature = signature_data[lib]
    location_fun_ = process_function(exported_signature.keys(), s , e)
    
    for fun in location_fun_:
        signature = exported_signature[fun]
        
        applyNewSignature(fun, location_fun_[fun], signature)
        applyComment(fun, location_fun_[fun] , lib)
        
        print(f"[AutoResolvIDATScripts] Done applying in all program new signature for function : {fun} linked to {lib} : signature : {signature}")
        



print("[AutoResolvIDATScripts] : save_data.py - end")    


idaapi.qexit(0) 
