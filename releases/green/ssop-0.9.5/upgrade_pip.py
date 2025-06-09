import pkg_resources
import subprocess
import sys
from ssop import settings

def run(cmdl, execute):
    """
    prints cmdl or passes it to subprocess.run if execute is True
    returns str
    """
    cmd = " ".join(cmdl)
    if execute:
        print("        running: " + cmd)
        result = subprocess.run(cmdl, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = str(result.stdout)
        if result.returncode != 0:
            print("Non-zero returncode: " + str(result.returncode))
            print("    result: " + str(result))
            print("    status: " + str(status))
            sys.exit(-1)
    else:
        print("    cmd: " + cmd)
        status = 'SUCCESS'
    return status


def basecmdl(pkgname):
    """
    returns a basic commands suitable for subprocess.run()
    """
    cmdl = ["pip3", "install", "--proxy", settings.HTTP_PROXY, "--upgrade", pkgname]
    return cmdl


for dist in pkg_resources.working_set:
    dist = str(dist)
    print(str(dist))
    packagename = str(dist).split()[0]
    cmdlist = basecmdl(packagename)
    runstatus = run(cmdlist, True)
