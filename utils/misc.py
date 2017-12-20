#!/usr/bin/python

from Aion.utils.data import *

import random, string, os, glob, subprocess, time, re
from datetime import datetime


def averageList(inputList, roundDigits=2):
   return round(float(sum(inputList))/float(len(inputList)), roundDigits)

def checkRoot():
    if os.getuid() != 0:
        return False
    else:
        return True

def getRandomNumber(length=8):
    return ''.join(random.choice(string.digits) for i in range(length))

def getRandomAlphaNumeric(length=8):
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def getRandomString(length=8):
    return ''.join(random.choice(string.lowercase) for i in range(length))

def getTimestamp(includeDate=False):
    if includeDate:
        return "[%s]"%str(datetime.now())
    else:
        return "[%s]"%str(datetime.now()).split(" ")[1]

def checkAVDState(vmName, vmState="running"):
    """
    Checks the current VirtualBox state of an AVD (e.g., running, stopping, ...)
    :param vmName: The name of the AVD to check
    :type vmName: str
    :param vmState: The status to check
    :type vmState: str
    :return: A boolean depicting whether the AVD is stuck and an str of its process ID
    """
    try:
        isStuck = False
        pID = ""
        vBoxInfoCmd = ["vboxmanage", "showvminfo", vmName]
        # Check whether the AVD is stuck in "Stopped" status
        status = subprocess.Popen(vBoxInfoCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        if status.lower().find(vmState) != -1:
            isStuck = True
            # Kill the VirtualBox process
            # a) Get UUID of stuck AVD
            uuid = ""
            for line in status.split('\n'):
                if line.find("UUID") != -1:
                    uuid = line[line.rfind(' ')+1:]
                    break 
            # b) Get the PID of the process
            ps = subprocess.Popen(["ps", "-eaf"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            ps.wait()
            out = subprocess.Popen(["grep", "-i", uuid], stdin=ps.stdout, stdout=subprocess.PIPE).communicate()[0]
            numbers = re.findall("\d+", out)
            if len(numbers) > 0:
                pID = str(numbers[0])

    except Exception as e:
        print "[*] Error encountered: %s" % e
        return False, ""
 
    return isStuck, pID

def restoreVirtualBoxSnapshot(vmName, snapshotName, retrials=25, waitToBoot=30):
    """
    Attempts to restore the snapshot of a VirtualBox machine
    :param vmName: The name of the virtual machine
    :type vmName: str
    :param snapshotName: The name of the snapshot to restore
    :type snapshotName: str
    :param retrials: In case of failure, how many attempts to restore the snapshot are made
    :type retrials: int
    :param waitToBoot:The time (in seconds) to wait for a virtual machine to boot
    :type waitToBoot: int
    :return: A boolean depicting the success/failure of the operation
    """
    try:
        # Define frequently-used commands
        vBoxRestoreCmd = ["vboxmanage", "snapshot", vmName, "restore", snapshotName]
        vBoxPowerOffCmd = ["vboxmanage", "controlvm", vmName, "poweroff"]
        genymotionStartCmd = [getGenymotionPlayer(), "--vm-name", vmName]
        genymotionPowerOffCmd = [getGenymotionPlayer(), "--vm-name", vmName, "--poweroff"]
        # Check whether the machine is stuck in the "Stopping" phase
        state, pID = checkAVDState(vmName, "stopping")
        if state:
            # Kill process
            print subprocess.Popen(["kill", pID], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        # Power off the genymotion AVD
        subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        # Make sure the AVD is dead
        state, pID = checkAVDState(vmName, "running")
        while state:
            subprocess.Popen(["kill", pID], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
            state, pID = checkAVDState(vmName, "running")
        
        # Attempt to restore the AVD's snapshot
        result = subprocess.Popen(vBoxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        counter = 0
        while result.lower().find("error") != -1:
            print result
            if counter == retrials:
                return False
            counter += 1
            result = subprocess.Popen(vBoxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
            time.sleep(1)
        # Power on the Genymotion AVD again
        poweron = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        state, pID = checkAVDState(vmName, "powered off")
        while state:
            time.sleep(10) # Sleep for 10 seconds
            poweron = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            state, pID = checkAVDState(vmName, "powered off")
 
        time.sleep(waitToBoot)

    except Exception as e:
        print e
        return False

    return True

# Copied from the "googleplay_api" helpers.py
def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f%s" % (num, x)
        num /= 1024.0

def specificity_score(ground_truth, predicted, classes=(1, 0)):
    try:
        if len(ground_truth) != len(predicted):
            return -1
        positive, negative = classes[0], classes[1]
        tp, tn, fp, fn = 0, 0, 0, 0
        for index in range(len(ground_truth)):
            if ground_truth[index] == negative and predicted[index] == negative:
                tn += 1
            elif ground_truth[index] == negative and predicted[index] == positive:
                fp += 1
            elif ground_truth[index] == positive and predicted[index] == negative:
                fn += 1
            else:
                tp += 1

        score = float(tn)/(float(tn)+float(fp))

    except Exception as e:
        print e
        return -1

    return score
