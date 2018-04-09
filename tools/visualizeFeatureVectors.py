#!/usr/bin/python

from Aion.data_generation.reconstruction.Numerical import *
from Aion.data_inference.visualization.visualizeData import *
from Aion.utils.graphics import *
from Aion.utils.data import *

import pickledb

import glob, sys, time, os, argparse, hashlib

def defineArguments():
    parser = argparse.ArgumentParser(prog="visualizeFeatureVectors.py", description="A tool to reduce the dimensionality of data points and visualize them in 2- or 3-D.")
    parser.add_argument("-p", "--datasetpath", help="The directory containing the feature vectors", required=True)
    parser.add_argument("-t", "--datasettype", help="The type of the feature vectors to load: indicates the type of experiment and the file extensions", required=True, choices=["static", "dynamic"])
    parser.add_argument("-a", "--algorithm", help="The dimensionality reduction algorithm to use", required=False, default="tsne", choices=["tsne", "pca"])
    parser.add_argument("-d", "--dimensionality", help="The target dimensionality to which the feature vectors are projected", required=False, default="2", choices=["2", "3"])
    parser.add_argument("-s", "--figuresize", help="The size of the Plotly figure", required=False, default="(1024, 1024)")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s experiment I")

        # Check the existence of the dataset directories
        if not os.path.exists("%s/malware/" % arguments.datasetpath) or not os.path.exists("%s/goodware/" % arguments.datasetpath):
            prettyPrint("Could not find malware or goodware directories under \"%s\". Exiting" % arguments.datasetpath, "warning")
            return False

        # Retrieve the data
        fileExtension = "static" if arguments.datasettype == "static" else "num"
        allFiles = glob.glob("%s/malware/*.%s" % (arguments.datasetpath, fileExtension)) + glob.glob("%s/goodware/*.%s" % (arguments.datasetpath, fileExtension))
        if len(allFiles) < 1:
            prettyPrint("Could not retrieve any \".%s\" files from the dataset directory \"%s\". Exiting" % (fileExtension, arguments.datasetpath), "warning")
            return False

        prettyPrint("Successfully retrieved %s \".%s\" files from the dataset directory \"%s\"" % (len(allFiles), fileExtension, arguments.datasetpath))
        # Load the data
        X, y = [], []
        appNames = []
        hashesDB = pickledb.load(getHashesDBPath(), False) # Open the hashes key-value store
        prettyPrint("Attempting to load feature vectors")
        for f in allFiles:
            featureVector = loadNumericalFeatures(f)
            if len(featureVector) < 1:
                continue
            else:
                # Retrieve app name from path
                appKey = f[f.rfind('/')+1:].replace(".%s" % fileExtension, "").lower()
                appName = hashesDB.get(appKey)
                if appName == None:
                   appKey = appKey + ".apk"
                   appName = hashesDB.get(hashlib.sha256(appKey).hexdigest())
                   if appName == None:
                       appName = f[f.rfind("/")+1:f.rfind(".")]
                   
                if f.lower().find("malware") != -1:
                    y.append(1)
                else:
                    y.append(0)
            
                X.append(featureVector)
                appNames.append(appName)
                if verboseON():
                    prettyPrint("App \"%s\" matched to package name \"%s\"" % (f, appName), "debug")

        if len(X) < 1:
            prettyPrint("Could not load any numerical feature vectors. Exiting", "warning")
            return False

        prettyPrint("Successfully retrieved and parsed %s numerical feature vectors" % len(X))
        # Perform visualization
        if arguments.datasettype == "static":
            # Retrieve different types of features
            X_basic = [x[:6] for x in X]   
            X_perm = [x[6:10] for x in X]
            X_api = [x[10:] for x in X]
           

            # Reduce and visualize features
            figureTitle = "Combined static features in %sD" % arguments.dimensionality
            prettyPrint("Visualizing combined static features in %sD" % arguments.dimensionality)
            reduceAndVisualize(X, y, int(arguments.dimensionality), arguments.algorithm, eval(arguments.figuresize), figureTitle, appNames=appNames)
            figureTitle = "Basic static features in %sD" % arguments.dimensionality
            prettyPrint("Visualizing basic features in %sD" % arguments.dimensionality)
            reduceAndVisualize(X_basic, y, int(arguments.dimensionality), arguments.algorithm, eval(arguments.figuresize), figureTitle, appNames=appNames)
            figureTitle = "Permission-based static features in %sD" % arguments.dimensionality
            prettyPrint("Visualizing permission-based features in %sD" % arguments.dimensionality)
            reduceAndVisualize(X_perm, y, int(arguments.dimensionality), arguments.algorithm, eval(arguments.figuresize), figureTitle, appNames=appNames)
            figureTitle = "API static features in %sD" % arguments.dimensionality
            prettyPrint("Visualizing API call features in %sD" % arguments.dimensionality)
            reduceAndVisualize(X_api, y, int(arguments.dimensionality), arguments.algorithm, eval(arguments.figuresize), figureTitle, appNames=appNames)
           
        else:
           figureTitle = "Dynamic Introspy features in %sD" % arguments.dimensionality
           reduceAndVisualize(X, y, int(arguments.dimensionality), arguments.algorithm, eval(arguments.figsize), figureTitle, appNames=appNames) 
    
    except Exception as e:
        prettyPrintError(e)
        return False

    return True

if __name__ == "__main__":
    main()
