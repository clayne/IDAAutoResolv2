import platform
import os
import lief

def get_platform():
    if platform.system() == 'Windows':
        return 'win'
    elif platform.system() == 'Linux':
        return 'linux'
    else:
        return None

def neverun():
    module_dir = os.path.dirname(__file__)
    run_once = os.path.join(module_dir, ".run_once")
    if not os.path.exists(run_once):
        with open(run_once,"w") as fd:
            fd.write("1")
            fd.close()
            
        return True
    
    return False

def getAllFunsFromLib(path):

    if "err_not_found" in path:
        return None
   
    exported_functions = {}

    library = lief.parse(path)
    exported_symbols = library.exported_symbols
    for symbol in exported_symbols:
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
            exported_functions[symbol.name] = symbol.name # not really usefull but can be used with get() in matchExternals()
    return exported_functions
        

# TODO : DO A BETTER CHECK FUNCTION (for exemple multiple libs path, multiples rpath, ...)
# TODO : DO A WINDOWS VERSION ALSO
def check_lib(libname, data_rpath, targetdir, custom_lib_dir=None):

    if custom_lib_dir is not None:
        path_lib = os.path.join(custom_lib_dir,libname)
        _exist = os.path.exists(path_lib)
        if _exist:
            return path_lib


    path_lib = os.path.join("/usr/lib/",libname)
    _exist = os.path.exists(path_lib)
    if _exist:
        return path_lib

    path_lib = os.path.join("/lib/x86_64-linux-gnu/",libname)
    _exist = os.path.exists(path_lib)
    if _exist:
        return path_lib
    
    if data_rpath == ".": #libs are in the target dir
        full_path = os.path.join(targetdir, libname)
    else:
        full_path = os.path.join(data_rpath, libname)

    return full_path


def matchExternals(externals, libs):
    resolved = {}

    #TODO : better algo search , optimization       
    for lib in libs:
        funs = getAllFunsFromLib(libs[lib])
        if len(funs) == 0:
            continue

        for external in externals:
            r = funs.get(external)
            if r is not None:
                resolved[external] = lib
                    
    return resolved

