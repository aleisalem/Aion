#!/usr/bin/python

from Aion.data_generation.reconstruction.Numerical import *
from Aion.data_inference.learning import ScikitLearners
from Aion.utils.db import *
from Aion.utils.graphics import *

import glob, sys,argparse

def defineArguments():
    parser = argparse.ArgumentParser(prog="staticExperimentI.py", description="A tool to implement the stimulation-detection feedback loop using Garfield as stimulation engine.")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-d", "--datasetname", help="A unique name to give to the dataset used in the experiment (for DB storage purposes)", required=True)     
    parser.add_argument("-f", "--featurestype", help="The type of static features to load", required=False, default="all", choices=["basic", "permission", "api", "all"])
    parser.add_argument("-r", "--runnumber", help="The number of the run", required=True)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s static experiment I")

        aionDB = AionDB(int(arguments.runnumber), arguments.datasetname)
        algorithms = aionDB.select([], "learner", [])
        learners = {}
        for a in algorithms.fetchall():
            if len(a) > 1:
                learners[a[1].lower()] = str(a[0])

        # 1. Load APK's and split into training and test datasets
        prettyPrint("Loading APK's from \"%s\" and \"%s\"" % (arguments.malwaredir, arguments.goodwaredir))
        # Retrieve malware APK's
        malFiles = glob.glob("%s/*.static" % arguments.malwaredir)
        if len(malFiles) < 1:
            prettyPrint("Could not find any malicious feature files" , "warning")
        else:
            prettyPrint("Successfully retrieved %s malicious feature files" % len(malFiles))
        # Retrieve goodware APK's
        goodFiles = glob.glob("%s/*.static" % arguments.goodwaredir)
        if len(goodFiles) < 1:
            prettyPrint("Could not find any benign feature files", "warning")
        else:
            prettyPrint("Successfully retrieved %s benign feature files" % len(goodFiles))

        # Split the data into training and test datasets
        malTraining, malTest = [], []
        goodTraining, goodTest = [], []
        malTestSize, goodTestSize = len(malFiles) / 3, len(goodFiles) / 3
        # Start with the malicious APKs
        while len(malTest) < malTestSize:
            malTest.append(malFiles.pop(random.randint(0, len(malFiles)-1)))
        malTraining += malFiles
        prettyPrint("[MALWARE] Training dataset size is %s, test dataset size is %s" % (len(malTraining), len(malTest)))
        # Same with benign APKs
        while len(goodTest) < goodTestSize:
            goodTest.append(goodFiles.pop(random.randint(0, len(goodFiles)-1)))
        goodTraining += goodFiles
        prettyPrint("[GOODWARE] Training dataset size is %s, test dataset size is %s" % (len(goodTraining), len(goodTest)))


        # 2. Load the feature vectors (Training)
        Xtr, ytr, Xte, yte = [], [], [], []
        for x in malTraining + goodTraining:
            v = loadNumericalFeatures(x)
            if len(v) > 0:
                # Vector
                if arguments.featurestype == "all":
                    Xtr.append(v)
                elif arguments.featurestype == "basic":
                    Xtr.append(v[:6])
                elif arguments.featurestype == "permission":
                    Xtr.append(v[6:10])
                else:
                    Xtr.append(v[10:])
                # Label
                if x in malTraining:
                    ytr.append(1)
                else:
                    ytr.append(0)

        # Load the feature vectors (Test)
        for x in malTest + goodTest:
            v = loadNumericalFeatures(x)
            if len(v) > 0:
                # Vector
                if arguments.featurestype == "all":
                    Xte.append(v)
                elif arguments.featurestype == "basic":
                    Xte.append(v[:6])
                elif arguments.featurestype == "permission":
                    Xte.append(v[6:10])
                else:
                    Xte.append(v[10:])
                # Label
                if x in malTest:
                    yte.append(1)
                else:
                    yte.append(0)


        # 3. Perform the classification
        metricsDict, metricsDict_test = {}, {}
        resultsFile = open("results_static_%s_%s_run%s.txt" % (arguments.datasetname, arguments.featurestype, arguments.runnumber), "w")
        prettyPrint("Ensemble mode classification: K-NN, SVM, and Random Forests using %s features" % arguments.featurestype)
        # Classifying using K-nearest neighbors
        K = [10, 25, 50, 100, 250, 500]
        for k in K:
            prettyPrint("Classifying using K-nearest neighbors with K=%s" % k)
            predicted, predicted_test = ScikitLearners.predictAndTestKNN(Xtr, ytr, Xte, yte, K=k)
            metrics = ScikitLearners.calculateMetrics(ytr, predicted)
            metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
            metricsDict["KNN%s" % k] = metrics
            metricsDict_test["KNN%s" % k] = metrics_test

        # Classifying using Random Forests
        E = [10, 25, 50, 75, 100]
        for e in E:
            prettyPrint("Classifying using Random Forests with %s estimators" % e)
            predicted, predicted_test = ScikitLearners.predictAndTestRandomForest(Xtr, ytr, Xte, yte, estimators=e)
            metrics = ScikitLearners.calculateMetrics(ytr, predicted)
            metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
            metricsDict["Trees%s" % e] = metrics
            metricsDict_test["Trees%s" % e] = metrics_test

        # Classifying using SVM
        prettyPrint("Classifying using Support vector machines")
        predicted, predicted_test = ScikitLearners.predictAndTestSVM(Xtr, ytr, Xte, yte)
        metrics = ScikitLearners.calculateMetrics(ytr, predicted)
        metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
        metricsDict["SVM"] = metrics
        metricsDict_test["SVM"] = metrics_test
                
        # Now do the majority voting ensemble
        allCs = ["KNN-%s" % x for x in K] + ["FOREST-%s" % e for e in E] + ["SVM"]
        predicted, predicted_test = ScikitLearners.predictAndTestEnsemble(Xtr, ytr, Xte, yte, classifiers=allCs)
        metrics = ScikitLearners.calculateMetrics(predicted, ytr) # Used to decide upon whether to iterate more
        metrics_test = ScikitLearners.calculateMetrics(predicted_test, yte)
        metricsDict["Ensemble"] = metrics
        metricsDict_test["Ensemble"] = metrics_test
      
        # Print and save results
        for m in metricsDict:
            # The average metrics for training dataset
            resultsFile.write("[TRAINING] Results for %s:\n" % m)
            resultsFile.write("%s\n" % str(metricsDict[m]))
            prettyPrint("Metrics using %s" % m, "output")
            prettyPrint("Accuracy: %s" % str(metricsDict[m]["accuracy"]), "output")
            prettyPrint("Recall: %s" % str(metricsDict[m]["recall"]), "output")
            prettyPrint("Specificity: %s" % str(metricsDict[m]["specificity"]), "output")
            prettyPrint("Precision: %s" % str(metricsDict[m]["precision"]), "output")
            prettyPrint("F1 Score: %s" %  str(metricsDict[m]["f1score"]), "output")
        
       
        # Print and save results [FOR THE TEST DATASET]
        for m in metricsDict_test:
            resultsFile.write("[TEST] Results for %s:\n" % m)
            resultsFile.write("%s\n" % str(metricsDict_test[m]))
            # The average metrics for training dataset
            prettyPrint("Metrics using cross validation and %s" % m, "output")
            prettyPrint("Accuracy: %s" % str(metricsDict_test[m]["accuracy"]), "output")
            prettyPrint("Recall: %s" % str(metricsDict_test[m]["recall"]), "output")
            prettyPrint("Specificity: %s" % str(metricsDict_test[m]["specificity"]), "output")
            prettyPrint("Precision: %s" % str(metricsDict_test[m]["precision"]), "output")
            prettyPrint("F1 Score: %s" %  str(metricsDict_test[m]["f1score"]), "output")
        

    except Exception as e:
        prettyPrintError(e)
        return False


    return True

if __name__ == "__main__":
    main()












