#!/usr/bin/python

from Aion.data_generation.reconstruction.Numerical import *
from Aion.data_inference.visualization.visualizeData import *
from Aion.utils.graphics import *

import glob, sys, time, os, argparse

def defineArguments():
    parser = argparse.ArgumentParser(prog="visualizeFeatureVectors.py", description="A tool to reduce the dimensionality of data points and visualize them in 2- or 3-D.")
    parser.add_argument("-p", "--datasetpath", help="The directory containing the feature vectors", required=True)
    parser.add_argument("-t", "--datasettype", help="The type of the feature vectors to load: indicates the type of experiment and the file extensions", required=True, choices=["static", "dynamic"])
    parser.add_argument("-a", "--algorithm", help="The dimensionality reduction algorithm to use", required=False, default="tsne", choices=["tsne", "pca"])
    parser.add_argument("-d", "--dimensionality", help="The target dimensionality to which the feature vectors are projected", required=False, default="2", choices=["2", "3"])
    parser.add_argument("-s", "--figuresize", help="The size of the Plotly figure", required=False, default="(800, 800)")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s experiment I")

        datasetPath = arguments.datasetpath
        datasetType = arguments.datasettype
        algorithm = arguments.algorithm
        dimensionality = int(arguments.dimensionality)
        figureSize = eval(arguments.figuresize)
        

        # Check the existence of the dataset directories
        if not os.path.exists("%s/malware/" % datasetPath) or not os.path.exists("%s/goodware/" % datasetPath):
            prettyPrint("Could not find malware or goodware directories under \"%s\". Exiting" % datasetPath, "warning")
            return False

        # Retrieve the data
        fileExtension = "static" if datasetType == "static" else "num"
        allFiles = glob.glob("%s/malware/*.%s" % (datasetPath, fileExtension)) + glob.glob("%s/goodware/*.%s" % (datasetPath, fileExtension))
        if len(allFiles) < 1:
            prettyPrint("Could not retrieve any \".%s\" files from the dataset directory \"%s\". Exiting" % (fileExtension, datasetPath), "warning")
            return False

        prettyPrint("Successfully retrieved %s \".%s\" files from the dataset directory \"%s\"" % (len(allFiles), fileExtension, datasetPath))
        # Load the data
        X, y = [], []
        prettyPrint("Attempting to load feature vectors")
        for f in allFiles:
            featureVector = loadNumericalFeatures(f)
            if len(featureVector) < 1:
                continue
            else:
                if f.lower().find("malware") != -1:
                    y.append(1)
                else:
                    y.append(0)
            
                X.append(featureVector)

        if len(X) < 1:
            prettyPrint("Could not load any numerical feature vectors. Exiting", "warning")
            return False

        prettyPrint("Successfully retrieved and parsed %s numerical feature vectors" % len(X))

        # Perform visualization
        if datasetType == "static":
            # Retrieve different types of features
            X_basic = [x[:6] for x in X]   
            X_perm = [x[6:10] for x in X]
            X_api = [x[10:] for x in X]
            
            # Reduce and visualize features
            figureTitle = "static_all_features_%sD" % dimensionality
            prettyPrint("Visualizing Static features in %s-D" % dimensionality)
            reduceAndVisualize(X, y, dimensionality, algorithm, figureSize, figureTitle)
            figureTitle = "static_basic_features_%sD" % dimensionality
            prettyPrint("Visualizing Basic features in %s-D" % dimensionality)
            reduceAndVisualize(X_basic, y, dimensionality, algorithm, figureSize, figureTitle)
            figureTitle = "static_permission_features_%sD" % dimensionality
            prettyPrint("Visualizing Permission-based features in %s-D" % dimensionality)
            reduceAndVisualize(X_perm, y, dimensionality, algorithm, figureSize, figureTitle)
            figureTitle = "static_api_features_%sD" % dimensionality
            prettyPrint("Visualizing API call features in %s-D" % dimensionality)
            reduceAndVisualize(X_api, y, dimensionality, algorithm, figureSize, figureTitle)
           
        else:
           figureTitle = "dynamic_features_%sD" % dimensionality
           reduceAndVisualize(X, y, dimensionality, algorithm, figSize, figureTitle) 
    
    except Exception as e:
        prettyPrintError(e)
        return False

    return True

if __name__ == "__main__":
    main()
