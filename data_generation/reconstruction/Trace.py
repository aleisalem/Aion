#!/usr/bin/python

from Aion.utils.data import *
from Aion.utils.graphics import *

import glob, os, json

def loadJSONTraces(jsonFiles, filesType="malware"):
    """Loads and parses JSON files in a list and returns a list of comma-separated traces"""
    try:
        allTraces = []
        for jsonFile in jsonFiles:
            currentAppName = jsonFile[jsonFile.rfind("/")+1:].replace(".json", "")
            # Check whether file exists
            if not os.path.exists(jsonFile):
                prettyPrint("JSON file \"%s\" could not be found. Skipping" % jsonFile, "warning")
            # Load JSON representation into python objects
            else:
                jsonTrace = json.loads(open(jsonFile).read())
                # Convert the JSON trace to a comma-separated string
                currentTrace = introspyJSONToTrace(jsonTrace)
                # Append trace to list
                if filesTypes == "malware":
                    allTraces.append((currentTrace, 1, currentAppName))
                elif fileTypes == "goodware":
                    allTraces.append((currentTrace, 0, currentAppName))
                else:
                    allTraces.append((currentTrace, -1, currentAppName))

    except Exception as e:
        prettyPrintError(e)
    
    return allTraces

def introspyJSONToTrace(jsonTrace):
    """Converts an Introspy-generated JSON trace to a comma-separated trace of API calls"""
    try:
        trace = []
        if not "calls" in jsonTrace.keys():
            prettyPrint("Could not find the key \"calls\" in current trace. Returning empty string", "warning")
            return ""
        # Iterate over the calls and append them to "trace"
        for call in jsonTrace["calls"]:
            callClass = call["clazz"]  # A "typo" in introspy's DBAnalyzer
            callMethod = call["method"][:call["method"].find(" - [WARNING")] if call["method"].find("WARNING") != -1 else call["method"]
            if "arguments" in call["argsAndReturnValue"].keys():
                #print call["argsAndReturnValue"]["arguments"].values()
                arguments = call["argsAndReturnValue"]["arguments"].values()#.sort()
                arguments = _cleanUpArgs(arguments)
                callArgs = ",".join(arguments) if arguments else ""
            # Append call to trace list
            trace.append(str("%s.%s(%s)" % (callClass, callMethod, callArgs)))

    except Exception as e:
        prettyPrintError(e)
        return ""

    return "|".join(trace)

def _cleanUpArgs(arguments):
    """Parses and cleans up a list of method arguments"""
    try:
        newArguments = []
        for arg in arguments:
            newArg = arg
            if arg.lower().find("intent") != -1:
                newArg = arg[arg.find("0:")+2:arg.rfind("]")]

            newArg = newArg.replace("[","").replace("]","")
            newArguments.append(newArg)

    except Exception as e:
        prettyPrintError(e)
        return arguments

    return newArguments
    
