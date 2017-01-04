#!/usr/bin/python

from Aion.utils.graphics import *
from Aion.utils.data import *

import numpy
import os

def loadNumericalFeatures(featuresFile, delimiter=","):
    """Loads numerical features from a file and returns a list"""
    try:
        if not os.path.exists(featuresFile):
            prettyPrint("Unable to find the features file \"%s\"" % featuresFile, "warning")
            return []
        content = open(featuresFile).read().split(delimiter)
        features = []
        for f in content:
            if f != "":
                features.append(float(f))

    except Exception as e:
        prettyPrintError(e)
        return []

    return features
