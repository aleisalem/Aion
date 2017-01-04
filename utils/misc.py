#!/usr/bin/python

import random, string, os, glob
from datetime import datetime

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

def averageList(inputList, roundDigits=2):
   return round(float(sum(inputList))/float(len(inputList)), roundDigits)

# Copied from the "googleplay_api" helpers.py
def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f%s" % (num, x)
        num /= 1024.0

def specificity_score(ground_truth, predicted, classes=(1, 0)):
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

    return float(tn)/(float(tn)+float(fp))
