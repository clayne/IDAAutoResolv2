import os

from libautoresolv2.util import get_platform,check_lib,matchExternals,encode
from libautoresolv2.action import run_ida_batchmode,craft_ida_command,run_idat

import shutil
"""
Author : 0xMirasio
"""

from libautoresolv2.log import Logger

class AutoResolv2Manager():
    def __init__(self, target, idat64_path , libdir=None, verbose=None, idadb=None):
        self.platform = get_platform()
        self.target = target
        self.libdir = libdir
        self.idat64_path = idat64_path
        self.verbose = verbose
        self.idadb = idadb

        if self.verbose:
            self.logger = Logger.get_logger(verbose=True)

        else:
            self.logger = Logger.get_logger()

        self.scripts = {}
        self.libs = {}
        self.signature = {}

        module_dir = os.path.dirname(__file__)
        scripts_dir = os.path.join(module_dir, "idat_scripts")
        scripts = os.listdir(scripts_dir)
        
        for script in scripts:
            self.scripts[script.replace('.py','')] = os.path.join(scripts_dir, script)

        self.prefix = "[AutoResolvIDATScripts]"
        

    def sanityCheck(self):

        if not os.path.exists(self.target):
            self.logger.error("[AutoResolv2] Target does not exist")
            return 1
        
        if not os.path.exists(self.idat64_path):
            self.logger.error("[AutoResolv2] idat64 binary does not exist")
            return 1
        
        if self.libdir is not None and not os.path.exists(self.libdir):
            self.logger.error("[AutoResolv2] Didn't found libdir...")
            return 1
        
        if self.idadb is not None and not os.path.exists(self.idadb):
            self.logger.error("[AutoResolv2] Didn't found given IDA database...")
            return 1
        
        self.dir_ = os.path.dirname(self.target)
        files = os.listdir(self.dir_)
        for file in files:
            if (self.target + ".til" in file) or (self.target + ".nam" in file) or (self.target + ".id0" in file):
                self.logger.warning("[AutoResolv2] Found opened target database in target directory ! Care, if you have opened the target binary in IDA, IDAT will not work !")
        
        return 0
    
    def make_idb(self):

        code = run_ida_batchmode(self.idat64_path, self.target, self.platform, verbose=self.verbose)
        if code:
            return 1
        
        self.target_db = self.target + ".i64"
        return 0
    
    def clean_temp(self):
        
        files = os.listdir(self.dir_)
        for file in files:
            file_path = os.path.join(self.dir_, file)
            if file_path.startswith(self.temp_binary):
                os.remove(file_path)

    def ping(self):
        
        cmd,logfile = craft_ida_command(self.idat64_path, self.target_db, self.scripts['ping'])
        code = run_idat(cmd, logfile, self.platform, self.verbose)
        if code:
            self.logger.error(f"Ping failed : {code} ")
            return 1
        
        output = open(logfile, "r")
        line = True
        while line:
            line = output.readline()
            if not self.prefix in line:
                continue
            if self.verbose:
                print(line.strip())


        return 0
    
    def get_all_externals(self):

        cmd,logfile = craft_ida_command(self.idat64_path, self.target_db, self.scripts['get_external'])
        code = run_idat(cmd, logfile, self.platform, self.verbose)
        if code:
            self.logger.error(f"get_external failed : {code} ")
            return 1
        
        data = None
        dataprefix = "[MANAGERDATA]"
        output = open(logfile, "r")
        line = True
        while line:
            line = output.readline()
            if not self.prefix in line:
                continue

            if dataprefix in line:
                data = line[len(dataprefix)+len(self.prefix)+1:].strip()
                continue
            if self.verbose:
                print(line.strip())

        if data is None:
            self.logger.error("Couldn't not gather externals from target")
            return 1
        
        # TODO : check if there is a way to convert into a list without dangerous eval call
        try:
            data_ = eval(data)
        except Exception as e:
            self.logger.error(f"Couldn't not cast data into a list => data = {data}, err ={str(e)}")
            return 1
        
        self.externals = data_
        return 0
    
    def get_libs_path(self):

        cmd,logfile = craft_ida_command(self.idat64_path, self.temp_binary, self.scripts['get_libs_path'], type='binary', do_not_scan=True)
        code = run_idat(cmd, logfile, self.platform, self.verbose)
        if code:
            self.logger.error(f"get_libs_path failed : {code} ")
            return 1
        
        data_libs = None
        dataprefix1 = "[MANAGERDATA1]"
        dataprefix2 = "[MANAGERDATA2]"
        data_rpath = None
        
        output = open(logfile, "r")
        line = True
        while line:
            line = output.readline()
            if not self.prefix in line:
                continue

            if dataprefix1 in line:
                data_libs = line[len(dataprefix1)+len(self.prefix)+1:].strip()
                continue

            if dataprefix2 in line:
                data_rpath = line[len(dataprefix2)+len(self.prefix)+1:].strip()
                continue

            if self.verbose:
                print(line.strip())

        if data_libs is None:
            self.logger.error("Couldn't not gather libs from target")
            return 1       
        
        try:
            data_libs_ = eval(data_libs)
        except Exception as e:
            self.logger.error(f"Couldn't not cast libs into a list => data = {data_libs}, err ={str(e)}")
            return 1
        
        if data_rpath is None:
            self.logger.error("CUSTOM RPATH : Not implemented yet !")
            return 1
       
        for lib in data_libs_:


            full_path = check_lib(lib, data_rpath, self.dir_, custom_lib_dir=self.libdir)
            self.logger.info("I have found linked lib to target: {0}".format(full_path))
            
            if not os.path.exists(full_path):
                self.logger.warning("Coulnd't find lib to target: {0} | Will not import function inside if exists !".format(full_path))
                self.logger.warning("Custom lib dir not implemented yet")
                self.libs[lib] = "err_not_found"
                continue

            self.libs[lib] = full_path
        
        return 0
    
    def get_data(self):


        for lib in self.libs:
            data = None
            dataprefix = "[MANAGERDATA]"
            pathlib  = self.libs[lib]

            fun_to_import = []
            for external in self.resolved:
                if self.resolved[external] == lib:
                    fun_to_import.append(external)

            self.logger.debug("Running idat for : {0}".format(pathlib))
            
            argument = encode(fun_to_import).decode()
            cmd,logfile = craft_ida_command(self.idat64_path, pathlib, self.scripts['get_data'], args = argument)
            code = run_idat(cmd, logfile, self.platform, self.verbose)
            if code:
                self.logger.error(f"get_data failed : {code} ")
                return 1
            
            output = open(logfile, "r")
            line = True
            while line:
                line = output.readline()
                if not self.prefix in line:
                    continue

                if dataprefix in line:
                    data = line[len(dataprefix)+len(self.prefix)+1:].strip()
                    continue

                if self.verbose:
                    print(line.strip())

            if data is None:
                self.logger.error(f"Couldn't not gather signature from {lib}")
                return 1
        
            try:
                data_ = eval(data)
            except Exception as e:
                self.logger.error(f"Couldn't not cast data into a dict => data = {data}, err ={str(e)}")
                return 1
            
            self.signature[lib] = data_
        
        return 0
    
    def save_data(self):
        
        argument = encode(self.signature).decode()
        cmd,logfile = craft_ida_command(self.idat64_path, self.target_db, self.scripts['save_data'], args = argument)
        code = run_idat(cmd, logfile, self.platform, self.verbose)
        if code:
            self.logger.error(f"save_data failed : {code} ")
            return 1
        
        output = open(logfile, "r")
        line = True
        while line:
            line = output.readline()
            if not self.prefix in line:
                continue

            if self.verbose:
                print(line.strip())



    def start(self):
    
        ### PHASE 1 : LETS HARVERST TARGET LINKED LIBS AND EXTERNALS FUNCTIONS

        if not self.idadb:
            self.logger.info(f"[AutoResolv2] Creating i64 database from {self.target}")
            if (self.make_idb()):
                self.logger.error(f"[AutoResolv2] Couldn't not create IDADB from {self.target}")
                return 1
            
            self.logger.info(f"[AutoResolv2] Created sucessfully {self.target_db}")
            
        else:
            self.target_db = self.idadb

        self.temp_binary = self.target + ".temp.bin"
        self.clean_temp()
        shutil.copy(self.target, self.temp_binary)
        
        if self.ping():
            return 1
        
        if self.get_all_externals():
            return 1
        
        if self.get_libs_path():
            return 1
        
        self.resolved = matchExternals(self.externals, self.libs)
        if len(self.resolved) == 0:
            self.logger.error("Didn't found any externals in the librairies")
            return 1      

        self.logger.info(f"Total of externals found with valids librairies : {len(self.resolved)}")  

        ### PHASE 2 : LETS IMPORT SIGNATURE AND STRUCTURE FROM TARGET LINKED LIBRARIES.

        if self.get_data():
            return 1
        
        self.logger.info("Done harvesting data, will save it in : {}".format(self.target_db))
        
        ### PHASE 3 : SAVE IT INTO TARGET DB

        if self.save_data():
            return 1

        self.logger.info(f"Done. Results are now inside {self.target_db}")








        
