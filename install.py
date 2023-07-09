import os
import shutil
import platform
import sys
### do not USE IT, THIS IS FOR FUTUR PROJECT ###

def main():
    print("Installing AutoResolv2")

    src_dir = os.path.dirname(__file__)
    
    src1 = os.path.join(src_dir, "autoresolv2.py")
    src2 = os.path.join(src_dir, "libautoresolv2")
    
    if platform.system() == 'Windows':

        print("Installing for windows")
        appdata = os.getenv("APPDATA")
        if appdata is None:
            print("No APPDATA environment variable !")
            return 1
        
        dst = os.path.join(appdata, "Hex-Rays\IDA Pro\plugins")

    elif platform.system() == 'Linux':
        
        print("Installing for linux")
        home = os.getenv('HOME')
        if home is None:
            print("No HOME environment variable set")
            return 1
        
        dst = os.path.join(home, ".idapro/plugins")

    else:
        print("System not suported")
        return 1
    
    dst1 = os.path.join(dst, "autoresolv2.py")
    dst2 = os.path.join(dst, "libautoresolv2")

    if os.path.exists(dst1):
        os.remove(dst1)
    if os.path.exists(dst2):
        shutil.rmtree(dst2)

    shutil.copy(src1, dst1)
    shutil.copytree(src2, dst2)
    
    print("Done installing plugin")


if __name__ == '__main__':
    if not os.path.exists(".debug"):
        print("Do not use this file. THIS IS FOR FUTURE PROJECT. you do not need to install anything for autoresolv2 right now")
        sys.exit(0)
    main()