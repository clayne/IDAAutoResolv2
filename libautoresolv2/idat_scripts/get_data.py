import idaapi
import idautils
import idc
import ida_funcs
import idc
import ida_hexrays
import base64

idaapi.auto_wait()

print("[AutoResolvIDATScripts] : get_data.py - starting")

fun_to_import = eval(base64.b64decode(idc.ARGV[1]))

def process_functions(funs):
    fun_matched_ = {}
    for seg_ea in idautils.Segments():
        for func_ea in idautils.Functions(seg_ea):
            func_name = ida_funcs.get_func_name(func_ea)

            if func_name in funs:
                fun_matched_[func_name] = func_ea

    return fun_matched_
                
def get_signature(ea):
    
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception:
        return "error:decompile"
    if cfunc:
        signature = str(cfunc.print_dcl())    
        signature_clean = ""
        for b in signature:
            if ord(b) > 30 and ord(b) < 127:
                signature_clean += b
                
        return signature_clean + ";"
        
        
    return "error:not_found"
    

fun_matched = process_functions(fun_to_import)

#TODO : EXPORT THE STRUCTURE IN THE ARGS THAT ARE DEFINED IN THE LIB

export = {}
for fun in fun_matched:
    signature = get_signature(fun_matched[fun])
    export[fun] = signature

print(f"[AutoResolvIDATScripts][MANAGERDATA]:{export}")

print("[AutoResolvIDATScripts] : get_data.py - end")    

idaapi.qexit(0) # i would like to personally insult the creator of ida python just for this function.