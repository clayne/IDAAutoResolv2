import subprocess
import os
import time
import tempfile
from libautoresolv2.log import Logger
logger = Logger.get_logger()

def run_idat(cmd, logfile, platform, verbose=None):

    if verbose:
        logger.debug(f"Running : {cmd}")

    dt1 = time.time()

    process = subprocess.Popen(cmd, shell=platform != "win")
    code = process.wait()

    dt2 = time.time()
    if verbose: 
       logger.debug("Finished ida scripts mode : {} seconds".format(dt2- dt1))

    try:
        output = open(logfile, "r")
    except FileNotFoundError:
        logger.error("[-] IDA script did not produce logs, return code: %d" % code)
        return False

    if code == 0:
        logger.info("IDA script terminated successfully.")

    else:
        logger.error("Trace:")
        logger.error(output.read())
        logger.error(f"[-] Status code:\t{hex(code)}")

        return code

    output.close()

def craft_ida_command(idat: str, idb: str, script: str, type=None, do_not_scan=None):

    exec_name = os.path.basename(idb).split(".")[0]
    log_file = tempfile.mktemp(prefix=f"{exec_name}_", suffix=".log")
    
    cmd = f'"{idat}" -A -L"{log_file}" -S\"{script}\"'

    if type:
        cmd += f" -T\"{type}\""

    if do_not_scan:
        cmd += " -a"
    
    cmd += f" {idb}"


    return (cmd, log_file)


def run_ida_batchmode(idat64_path, target, platform,verbose=None):
    
    args = f'"{idat64_path}" -B "{target}"'
    process = subprocess.Popen(args, shell=(platform != "win"))

    dt1 = time.time()
    if verbose: 
        logger.debug("Started ida batch mode")

    code = process.wait()
    if code != 0:
        return code

    os.remove(target + ".asm")

    dt2 = time.time()
    if verbose: 
       logger.debug("Finished ida batch mode : {} seconds".format(dt2- dt1))


    return 0

