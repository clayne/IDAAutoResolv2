import argparse
from libautoresolv2.config import VERSION
from libautoresolv2.manager import AutoResolv2Manager
from libautoresolv2.util import neverun
from libautoresolv2.log import Logger
logger = Logger.get_logger()

def main():
    parser = argparse.ArgumentParser(description='Autoresolv2')
    parser.add_argument('-t', '--target', help='Your binary', required=True)
    parser.add_argument('-I', '--idat', help='Path to IDA PRO idat64 binary', required=True)
    parser.add_argument('-D', '--idadb', help='Give a additional IDA DB which will be used for storing parsed data')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-S', '--libdir', help='Specify a custom directory for used libraries')
    args = parser.parse_args()

    
    logger.info(f"IDAAutoResolv2 Command Line {VERSION}")

    if neverun():
        logger.warning("[Warning] If idat64 never run, config can be asked so most of scripts will fail. Please run at least one time idat64 to prevent this.")

    manager = AutoResolv2Manager(args.target, args.idat, args.libdir, args.verbose, args.idadb)
    if manager.sanityCheck():
        logger.critical("[AutoResolv2] Sanity check failed")
        return
    
    if (manager.start()):
        logger.critical("[AutoResolv2] Exit to due critical error in manager")
        return 
    

if __name__ == '__main__':
    main()