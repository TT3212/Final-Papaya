import sys
import subprocess

# implement pip as a subprocess:
def installation_of_packages():
    requirements = open("requirements.txt", "r")
    require = requirements.read()
    required_packages = require.split()
    reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'])
    installed_packages = [r.decode() for r in reqs.split()]
    for i in range(0, len(required_packages)):
        if required_packages[i] not in installed_packages:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', required_packages[i]])


