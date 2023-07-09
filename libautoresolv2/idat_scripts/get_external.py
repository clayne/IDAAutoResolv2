import idaapi
import idautils
import idc
import ida_funcs

idaapi.auto_wait()

FILTER_LIBC = [
     
     "__libc_start_main", "__stack_chk_fail", "__printf_chk", "__imp___cxa_finalize",
     "_ITM_deregisterTMCloneTable", "__gmon_start__", "_ITM_registerTMCloneTable"


]

print("[AutoResolvIDATScripts] : get_external.py - starting")

def get_seg(segname):
        for s in idautils.Segments():
            seg = idaapi.getseg(s)
            name = idc.get_segm_name(s)
            if name == segname:
                start = seg.start_ea
                end = seg.end_ea
                return start, end
        
        return None,None
        
def get_extern(s,e):
    external = []
    funs = idautils.Functions(start = s, end=e)
    for ea in funs:
        px = ida_funcs.get_func_name(ea)
        flags = idc.get_func_flags(ea)
        if str(px).startswith("sub_"):
            continue
        if (flags & 0x80): #all external functions are wrapper -> jump OFFSET, so flags ISJUMP should be 1
            to_add = px[1:] #remove prefix . from function
            if to_add in FILTER_LIBC:
                 continue
            external.append(to_add)
        
    return external


start_plt,end_plt = get_seg(".plt.sec")
externals = get_extern(start_plt, end_plt)

print(f"[AutoResolvIDATScripts][MANAGERDATA]:{externals}")

print("[AutoResolvIDATScripts] : get_external.py - end")    
idaapi.qexit(0)