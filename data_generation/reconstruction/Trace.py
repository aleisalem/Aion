#!/usr/bin/python

from Aion.utils.data import *
from Aion.utils.graphics import *

import glob, os, json

def loadJSONTraces(jsonFiles):
    """Loads and parses JSON files in a list and returns a list of comma-separated traces"""
    try:
        allTraces = []
        for jsonFile in jsonFiles:
            # Check whether file exists
            if not os.path.exists(jsonFile):
                prettyPrint("JSON file \"%s\" could not be found. Skipping" % jsonFile, "warning")
            # Load JSON representation into python objects
            else:
                jsonTrace = json.loads(open(jsonFile).read())
                # Convert the JSON trace to a comma-separated string
                currentTrace = jsonToTrace(jsonTrace)
                # Append trace to list
                allTraces.append(currentTrace)

    except Exception as e:
        prettyPrintError(e)
    
    return allTraces

def jsonToTrace(jsonTrace):
    """Converts a JSON trace to a comma-separated trace of API calls"""
    try:
        trace = []
        if not "calls" in jsonTrace.keys():
            prettyPrint("Could not find the key \"calls\" in current trace. Returning empty string", "warning")
            return ""
        # Iterate over the calls and append them to "trace"
        for call in jsonTrace["calls"]:
            callClass = call["class"]
            callMethod = call["method"][:call["method"].rfind(" ")]
            if "arguments" in call["argsAndReturnValue"].keys():
                arguments = call["argsAndReturnValue"]["arguments"].values().sort()
                callArgs = ",".arguments
            # Append call to trace list
            trace.append("%s.%s(%s)" % (callClass, callMethod, callArgs))

    except Exception as e:
        prettyPrintError(e)
        return ""

    return ",".join(trace)
