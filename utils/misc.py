#!/usr/bin/python

from Aion.utils.data import *

import random, string, os, glob, subprocess, time
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

def restoreVirtualBoxSnapshot(vmName, snapshotName, retrials=10, waitToBoot=30):
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
        genymotionPowerOffCmd = [getGenymotionPlayer(), "--poweroff", "--vm-name", vmName]
        # Power off the genymotion AVD
        subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        # Attempt to restore the AVD's snapshot
        result = subprocess.Popen(vBoxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
        counter = 0
        while result.lower().find("error") != -1:
            print result
            if counter == retrials:
                return False
            counter += 1
            print "[*] Failed to restore snapshot. Retrying #%s" % counter
            result = subprocess.Popen(vBoxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
            time.sleep(1)
        # Power on the Genymotion AVD again
        poweron = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        #poweron.wait() # TODO: Returns only after machine exits
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
