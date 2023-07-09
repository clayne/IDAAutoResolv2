import idaapi
import ida_segment
import ida_loader
import idautils
import tempfile
import ida_bytes
import lief

idaapi.auto_wait()

print("----------------------------------------------------------------")
print("[AutoResolvIDATScripts] : get_libs_path.py - starting")

def get_seg(segname):
        for s in idautils.Segments():
            seg = idaapi.getseg(s)
            name = idc.get_segm_name(s)
            if name == segname:
                start = seg.start_ea
                end = seg.end_ea
                return start, end
        
        return None,None
    
start_LOAD,end_LOAD = get_seg("seg000")
total_size_binary = end_LOAD - start_LOAD

project_name = idaapi.get_root_filename()
binary_temp = tempfile.mktemp(prefix=f"{project_name}_", suffix=".tempbin")

print(f"[AutoResolvIDATScripts] Saving temp binary to : {binary_temp}")

binary_ = ida_bytes.get_bytes(start_LOAD, total_size_binary)

with open(binary_temp,"wb") as fd:
    fd.write(binary_)
    fd.close()
    
print("[AutoResolvIDATScripts] Using lief to parse binary info.")

def get_linked_libraries_and_runpath(binary_path):
    binary = lief.parse(binary_path)

    linked_libraries = []
    runpath = None

    for library in binary.libraries:
        if library.startswith("libc.so"):
            continue
        linked_libraries.append(library)

    dynamic_entries = binary.dynamic_entries
    for entry in dynamic_entries:
        if entry.tag == lief.ELF.DYNAMIC_TAGS.RUNPATH:
            runpath = entry.name

    return linked_libraries, runpath

linked_libraries, runpath = get_linked_libraries_and_runpath(binary_temp)

if len(linked_libraries) > 0:
    print(f"[AutoResolvIDATScripts][MANAGERDATA1]:{linked_libraries}")

if runpath is not None:
    print(f"[AutoResolvIDATScripts][MANAGERDATA2]:{runpath}")

print("[AutoResolvIDATScripts] : get_libs_path.py - end")    

idaapi.qexit(0)