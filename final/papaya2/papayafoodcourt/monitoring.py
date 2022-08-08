import sys
import subprocess
import re
import nvdlib
from requirements import installation_of_packages

requirements = open("requirements.txt", "r")
require = requirements.read()
required_packages = require.split()


def packages_req():
    packages_list = []
    for values in required_packages:
        packages_list.append(values.split('=='))
    return packages_list

packages_name = []
packages_list = packages_req()
for i in range(len(packages_list)):
    packages_name.append(packages_list[i][0])


def updated_lib():
    updated_list = []
    update_req = subprocess.check_output([sys.executable, '-m', 'pip', 'list', '--uptodate'])
    updated_packages = [r.decode() for r in update_req.split()]
    for i in range(0,len(updated_packages[4:])):
        for values in packages_name:
            if values == updated_packages[4:][i]:
                values = [values, updated_packages[4:][i+1]]
                updated_list.append(values)
    return updated_list


def outdated_lib():
    outdated_lists = []
    reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'list', '--outdated'])
    outdated_packages = [r.decode() for r in reqs.split()]
    for i in range(0,len(outdated_packages[8::2])):
        for values in packages_name:
            if values == outdated_packages[8::2][i]:
                values = [values, outdated_packages[8::2][i + 1]]
                outdated_lists.append(values)
    return outdated_lists


def update_module(library):
    library = library.strip("']['").split("', '")
    subprocess.run([sys.executable, '-m', 'pip', library[0], '--upgrade'])
    with open('requirements.txt', 'r+') as f:
        text = f.read()
        og = library[0] + '==' + library[1]
        change = library[0] + '==' + library[2]
        text = re.sub(og, change, text)
        f.seek(0)
        f.write(text)
        f.truncate()
    installation_of_packages()


def freeze_check():
    missing_packages = []
    reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'])
    installed_packages = [r.decode() for r in reqs.split()]
    for i in range(0, len(required_packages)):
        if installed_packages[i] not in required_packages:
            missing_packages.append(installed_packages[i].split('=='))
    return missing_packages


def adding_package(package):
    package = package.strip("']['").split("', '")
    with open('requirements.txt', 'a+') as f:
        f.seek(0)
        f.write("\n")
        f.write(package[0] + "==" + package[1])
    installation_of_packages()


def sorting(theSeq):
    n = len(theSeq)
    for i in range(n - 1, 0, -1):
        noSwap = True
        for j in range(i):
            if theSeq[j][0].upper() > theSeq[j + 1][0].upper():
                tmp = theSeq[j]
                theSeq[j] = theSeq[j + 1]
                theSeq[j + 1] = tmp
                noSwap = False
        if noSwap:
            break
    return theSeq
