#!/usr/bin/python

from Aion.data_generation.stimulation.Garfield import Garfield
from Aion.data_generation.reconstruction import *
from Aion.data_inference.learning import HMM, ScikitLearners
from Aion.data_inference.extraction.featureExtraction import *
from Aion.utils.data import *     # Needed for accessing configuration files
from Aion.utils.graphics import * # Needed for pretty printing
from Aion.utils.misc import *
from Aion.shared.DroidutanTest import * # The Droidutan-drive test thread

from sklearn.metrics import *
import numpy, ghmm
import introspy # Used for analysis of introspy generated databases
from droidutan import Droidutan

import os, sys, glob, shutil, argparse, subprocess, sqlite3, time, threading



def defineArguments():
    parser = argparse.ArgumentParser(prog="runExperimentI.py", description="A tool to implement the stimulation-detection feedback loop using Garfield as stimulation engine.")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-m", "--malwaredirtest", help="The directory containing the malicious APK's to analyze and use as test dataset", required=True)
    parser.add_argument("-b", "--goodwaredirtest", help="The directory containing the benign APK's to analyze and use as test dataset .", required=True)  
    parser.add_argument("-f", "--analyzeapks", help="Whether to perform analysis on the retrieved APK's", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-t", "--analysistime", help="How long to run monkeyrunner (in seconds)", required=False, default=60)
    parser.add_argument("-v", "--vmnames", help="The name(s) of the Genymotion machine(s) to use for analysis (comma-separated)", required=False, default="")
    parser.add_argument("-z", "--vmsnapshots", help="The name(s) of the snapshot(s) to restore before analyzing an APK (comma-separated)", required=False, default="")
    parser.add_argument("-a", "--algorithm", help="The machine learning algorithm to use for classification", required=True, choices=["trees", "svm", "knn", "ensemble"])
    parser.add_argument("-k", "--kfold", help="Whether to use k-fold cross validation and the value of \"K\"", required=False, default=2)
    parser.add_argument("-s", "--selectkbest", help="Whether to select K best features from the ones extracted from the APK's", required=False, default=0)
    parser.add_argument("-e", "--featuretype", help="The type of features to consider during training", required=False, default="hybrid", choices=["static", "dynamic", "hybrid"])
    parser.add_argument("-p", "--fileextension", help="The extension of feature files", required=False, default="txt")
    parser.add_argument("-u", "--svmusessk", help="Whether to use the SSK kernel with SVM", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-n", "--svmsubsequence", help="The length of the subsequence to consider upon using SVM's with the SSK", required=False, default=3)
    parser.add_argument("-o", "--outfile", help="The path to the file to log classification results", required=False, default="")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s experiment I")

        if arguments.vmnames == "":
            prettyPrint("No virtual machine names were supplied. Exiting", "warning")
            return False

        iteration = 1 # Initial values
        reanalysis = False
        currentMetrics = {"accuracy": 0.0, "recall": 0.0, "specificity": 0.0, "precision": 0.0, "f1score": 0.0}
        previousMetrics = {"accuracy": -1.0, "recall": -1.0, "specificity": -1.0, "precision": -1.0, "f1score": -1.0}
        reanalyzeMalware, reanalyzeGoodware = [], [] # Use this as a cache until conversion
        allVMs = arguments.vmnames.split(',')
        allSnapshots = arguments.vmsnapshots.split(',')
        availableVMs = [] + allVMs # Initially

        while currentMetrics["f1score"] > previousMetrics["f1score"]:
            reanalysis = True if iteration > 1 else False
            prettyPrint("Experiment I: iteration #%s" % iteration, "info2")
            iteration += 1
            if arguments.analyzeapks == "yes":
                # Retrieve malware APK's
                malAPKs = reanalyzeMalware if reanalysis else glob.glob("%s/*.apk" % arguments.malwaredir) + glob.glob("%s/*.apk" % arguments.malwaredirtest)
                if len(malAPKs) < 1:
                    prettyPrint("Could not find any malicious APK's" , "warning")
                else:
                    prettyPrint("Successfully retrieved %s malicious instances" % len(malAPKs))
                # Retrieve goodware APK's
                goodAPKs = reanalyzeGoodware if reanalysis else glob.glob("%s/*.apk" % arguments.goodwaredir) + glob.glob("%s/*.apk" % arguments.goodwaredirtest)
                if len(goodAPKs) < 1:
                    prettyPrint("Could not find any benign APK's", "warning")
                else:
                    prettyPrint("Successfully retrieved %s benign instances" % len(goodAPKs))

                allAPKs = malAPKs + goodAPKs
                if len(allAPKs) < 1:
                    prettyPrint("Could not find any APK's to analyze", "error")
                    return False
                
                ########################
                ## Main Analysis Loop ##
                ########################
                currentProcesses = []
                while len(allAPKs) > 0:

                    # Step 1. Pop an APK from "allAPKs" (Defaut: last element)
                    currentAPK = allAPKs.pop()

                    # Ignore previously-analyzed APK's that are not in for re-analysis
                    if not reanalysis:
                        if os.path.exists(currentAPK.replace(".apk", ".db")):# % arguments.fileextension)):
                            prettyPrint("APK \"%s\" has been analyzed before. Skipping" % currentAPK, "warning")
                            continue 
                    else:
                        # Second line of defense
                        if not currentAPK in reanalyzeMalware + reanalyzeGoodware:
                            prettyPrint("APK \"%s\" has been analyzed before. Skipping" % currentAPK, "warning")
                            continue

                    # Step 2. Check availability of VMs for test
                    while len(availableVMs) < 1:
                        prettyPrint("No AVD's available for analysis. Sleeping for 10 seconds")# % arguments.analysistime)
                        print [p.name for p in currentProcesses]
                        print [p.is_alive() for p in currentProcesses]
                        # 2.a. Sleep for "analysisTime"
                        time.sleep(10)
                        # 2.b. Check for available machines
                        for p in currentProcesses:
                            if not p.is_alive():
                                if verboseON():
                                     prettyPrint("Process \"%s\" is dead. A new AVD is available for analysis" % p.name, "debug")
                                availableVMs.append(p.name)
                                currentProcesses.remove(p)

                        print [p.name for p in currentProcesses]
                        print [p.is_alive() for p in currentProcesses]

                    # Step 3. Pop one VM from "availableVMs"
                    currentVM = availableVMs.pop()

                    if verboseON():
                        prettyPrint("Running \"%s\" on AVD \"%s\"" % (currentAPK, currentVM))

                    # Step 4. Start the analysis thread
                    pID = int(time.time())
                    p = DroidutanAnalysis(pID, currentVM, (currentVM, ), currentAPK, int(arguments.analysistime))
                    p.daemon = True # Process will be killed if main thread exits
                    p.start()
                    currentProcesses.append(p)
                      
                    prettyPrint("%s APKs left to analyze" % len(allAPKs), "output")
    

                # Just make sure all VMs are done
                while len(availableVMs) < len(allVMs):
                    prettyPrint("Waiting for AVD's to complete analysis")
                    # 2.a. Sleep for "analysisTime"
                    time.sleep(int(arguments.analysistime))
                    # 2.b. Check for available machines
                    for p in currentProcesses:
                        if not p.is_alive():
                            availableVMs.append(p.name)
                            currentProcesses.remove(p)

                ########################################################
                ## Analyze all introspy database files after analysis ##
                ########################################################
                # Step 0. Retrieve all introspy database files
                allDBFiles = glob.glob("%s/*.db" % arguments.malwaredir)
                allDBFiles += glob.glob("%s/*.db" % arguments.goodwaredir)
                allDBFiles += glob.glob("%s/*.db" % arguments.malwaredirtest)
                allDBFiles += glob.glob("%s/*.db" % arguments.goodwaredirtest)
                if len(allDBFiles) < 1:
                    prettyPrint("Could not retrieve an database files to analyze. Exiting", "warning")

                prettyPrint("Successfully retrieved %s introspy database files to analyze" % len(allDBFiles))
                # Step 1. Analyze the downloaded database
                for dbFile in allDBFiles:
                    # 1.a. Check that the database exists and is not empty
                    if int(os.path.getsize(dbFile)) == 0:
                        prettyPrint("The database generated by Introspy is empty. Skipping", "warning")
                        continue
                    # Last line of defense
                    try:
                        prettyPrint("Analyzing the Introspy database file \"%s\"" % dbFile)
                        db = introspy.DBAnalyzer(dbFile, "foobar")
                    except sqlite3.OperationalError as sql:
                        prettyPrint("The database generated by Introspy is probably empty. Skipping", "warning")
                        continue
                    except sqlite3.DatabaseError as sql:
                        prettyPrint("Database image is malformed. Skipping", "warning")
                        continue

                    jsonTrace = db.get_traced_calls_as_JSON()

                    # Step 2. Write trace to malware/goodware dir
                    # 2.a. Get a handle
                    if dbFile.find("malware") != -1: 
                         if dbFile.find("training") != -1:
                             jsonTraceFile = open(dbFile.replace(".db", ".json"), "w")
                         else:
                             jsonTraceFile = open(dbFile.replace(".db", ".json"), "w")
                    else:
                        if dbFile.find("training") != -1:
                            jsonTraceFile = open(dbFile.replace(".db", ".json"), "w")
                        else:
                            jsonTraceFile = open(dbFile.replace(".db", ".json"), "w")
                    # 7.b. Write content
                    jsonTraceFile.write(jsonTrace)
                    jsonTraceFile.close()

                    # 7.c. Extract and save numerical features for SVM's and Trees
                    prettyPrint("Extracting hybrid features from APK")
                    staticFeatures, dynamicFeatures = extractAndroguardFeatures(dbFile.replace(".db", ".apk")), extractIntrospyFeatures(jsonTraceFile.name)
                    if len(staticFeatures) < 1 or len(dynamicFeatures) < 1:
                        prettyPrint("An error occurred while extracting static or dynamic features. Skipping", "warning")
                        continue
                    # Otherwise, store the features
                    if arguments.featuretype == "static":
                        features = staticFeatures
                    elif arguments.featuretype == "dynamic":
                        features = dynamicFeatures
                    else:
                        features = staticFeatures + dynamicFeatures # TODO: Can static features help with the mediocre specificity scores?
                    if dbFile.find("malware") != -1:
                        if dbFile.find("training") != -1:
                            featuresFile = open(dbFile.replace(".db", ".%s" % arguments.fileextension), "w")
                        else:
                            featuresFile = open(dbFile.replace(".db", ".%s" % arguments.fileextension), "w")
                    else:
                        if dbFile.find("training") != -1:
                            featuresFile = open(dbFile.replace(".db", ".%s" % arguments.fileextension), "w")
                        else:
                           featuresFile = open(dbFile.replace(".db", ".%s" % arguments.fileextension), "w")


                    featuresFile.write("%s\n" % str(features)[1:-1])
                    featuresFile.close()

                    prettyPrint("Done analyzing \"%s\"" % dbFile)
                    
                    # Delete old introspy.db file
                    #os.remove(dbFile)

            ####################################################################
            # Load the JSON  and feature files as traces before classification #
            ####################################################################
            # Load numerical features
            allFeatureFiles = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.fileextension)) + glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.fileextension))
            allFeatureFilesTest = glob.glob("%s/*.%s" % (arguments.malwaredirtest, arguments.fileextension)) + glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.fileextension))
            allTraceFiles = glob.glob("%s/*.json" % arguments.malwaredir) + glob.glob("%s/*.json" % arguments.goodwaredir)
            allTraceFilesTest = glob.glob("%s/*.json" % arguments.malwaredirtest) + glob.glob("%s/*.json" % arguments.goodwaredirtest)
               
            prettyPrint("Retrieved %s feature files (%s for testing) and %s trace files (%s for testing)" % (len(allFeatureFiles), len(allFeatureFilesTest), len(allTraceFiles), len(allTraceFilesTest)))
 
            metrics, metrics_test = {}, {}
            
            ###########################
            # Support Vector Machines #
            ###########################
            if arguments.algorithm == "svm":
                prettyPrint("Classifying using Support Vector Machines")
                X, y = [], []
                Xtest, ytest = [], []
                if arguments.svmusessk == "yes":
                    prettyPrint("Using the String Subsequence Kernel (SSK)")
                    # Loading training feature vectors
                    for f in allTraceFiles:
                        X.append(introspyJSONToTrace(f))
                        # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                        if f.find("malware") != -1:
                            y.append(1)
                        else:
                            y.append(0)
                    # Loading test feature vectors
                    for f in allTraceFilesTest:
                        Xtest.append(introspyJSONToTrace(f))
                        # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                        if f.find("malware") != -1:
                            ytest.append(1)
                        else:
                            ytest.append(0)
                        
                     
                    predicted, predicted_test = ScikitLearners.predictedAndTestKFoldSVMSSK(X, y, Xtest, ytest, kfold=int(arguments.kfold), subseqLength=int(arguments.svmsubsequence), selectKBest=int(arguments.selectKBest))

                else:
                    # Loading training feature vectors
                    for f in allFeatureFiles:
                         X.append(Numerical.loadNumericalFeatures(f))
                         # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                         if f.find("malware") != -1:
                             y.append(1)
                         else:
                             y.append(0)

                    # Loading test feature vectors
                    for f in allFeatureFilesTest:
                        Xtest.append(Numerical.loadNumericalFeatures(f))
                        # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                        if f.find("malware") != -1:
                            ytest.append(1)
                        else:
                            ytest.append(0)                        

                    predicted, predicted_test = ScikitLearners.predictAndTestKFoldSVM(X, y, Xtest, ytest, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))

                metrics, metrics_test = ScikitLearners.calculateMetrics(y, predicted), ScikitLearners.calculateMetrics(ytest, predicted_test)

            ##################
            # Decision Trees #
            ##################
            elif arguments.algorithm == "tree":
                prettyPrint("Classifying using Decision Trees")

                X, y = [], []
                Xtest, ytest = [], []
                # Loading training feature vectors
                for f in allFeatureFiles:
                    X.append(Numerical.loadNumericalFeatures(f))
                    # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                    if f.find("malware") != -1:
                        y.append(1)
                    else:
                        y.append(0)
                # Loading test feature vectors
                for f in allFeatureFilesTest:
                    Xtest.append(Numerical.loadNumericalFeatures(f))
                    # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                    if f.find("malware") != -1:
                        ytest.append(1)
                    else:
                        ytest.append(0)

                predicted, predicted_test = ScikitLearners.predictAndTestKFoldTrees(X, y, Xtest, ytest, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))
                metrics, metrics_test = ScikitLearners.calculateMetrics(y, predicted), ScikitLearners.calculateMetrics(ytest, predicted_test)

            ####################################
            # Ensemble of learning algorithms #
            ###################################
            elif arguments.algorithm == "ensemble":
                prettyPrint("Ensemble mode classification: K-NN, SVM, and Random Forests")
                X, y = [], []
                Xtest, ytest = [], []
                # Loading training feature vectors
                for f in allFeatureFiles:
                    X.append(Numerical.loadNumericalFeatures(f))
                    # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                    if f.find("malware") != -1:
                        y.append(1)
                    else:
                        y.append(0)
                # Loading test feature vectors
                for f in allFeatureFilesTest:
                    Xtest.append(Numerical.loadNumericalFeatures(f))
                    # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                    if f.find("malware") != -1:
                        ytest.append(1)
                    else:
                        ytest.append(0)

                # Classifying using K-nearest neighbors
                K = [10, 25, 50, 100, 250, 500]
                metricsDict, metrics_testDict = {}, {}
                tmpPredicted, tmpPredicted_test = [0]*len(y), [0]*len(y)
                for k in K:
                    prettyPrint("Classifying using K-nearest neighbors with K=%s" % k)
                    predicted, predicted_test = ScikitLearners.predictAndTestKFoldKNN(X, y, Xtest, ytest, K=k, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))
                    for i in range(len(predicted)):
                        tmpPredicted[i] += predicted[i]
                        tmpPredicted_test[i] += predicted_test[i]
                    metrics, metrics_test = ScikitLearners.calculateMetrics(y, predicted), ScikitLearners.calculateMetrics(ytest, predicted_test)
                    metricsDict["KNN%s" % k] = metrics
                    metrics_testDict["KNN%s" % k] = metrics_test

                # Classifying using Random Forests
                E = [10, 25, 50, 75, 100]
                for e in E:
                    prettyPrint("Classifying using Random Forests with %s estimators" % e)
                    predicted, predicted_test = ScikitLearners.predictAndTestKFoldTree(X, y, Xtest, ytest, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))
                    for i in range(len(predicted)):
                        tmpPredicted[i] += predicted[i]
                        tmpPredicted_test[i] += predicted_test[i]
                    metrics, metrics_test = ScikitLearners.calculateMetrics(y, predicted), ScikitLearners.calculateMetrics(ytest, predicted_test)
                    metricsDict["Trees%s" % e] = metrics
                    metrics_testDir["Trees%s" % e] = metrics_test

                # Classifying using SVM
                prettyPrint("Classifying using Support vector machines")
                predicted, predicted_test = ScikitLearners.predictAndTestKFoldSVM(X, y, Xtest, ytest, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))
                for i in range(len(predicted)):
                    tmpPredicted[i] += predicted[i]
                    tmpPredicted_test[i] += predicted_test[i]
                metrics, metrics_test = ScikitLearners.calculateMetrics(y, predicted), ScikitLearners.calculateMetrics(ytest, predicted_test)
                metricsDict["svm"] = metrics
                metrics_testDict["svm"] = metrics_test
                
                # Average the predictions in tempPredicted and tempPredicted_test
                predicted, predicted_test = [-1]*len(y), [-1]*len(y)
                for i in range(len(tmpPredicted)):
                    predicted[i] = 1 if tmpPredicted[i]/12 >= 6 else 0 # 12 classifiers
                    predicted_test[i] = 1 if tmpPredicted_test[i] / 12 >=6 else 0 # 12 classifiers

                metricsDict["all"] = calculateMetrics(predicted, y)
                metrics_testDict["all"] = calculateMetrics(predicted_test, ytest)
        
                metrics, metrics_test = metricsDict["all"], metrics_testDict["all"] # Used to decide upon whether to iterate more
      
            # Print and save results
            if arguments.algorithm == "ensemble":
                for m in metricsDict:
                    # The average metrics for training dataset
                    prettyPrint("Metrics using %s-fold cross validation and %s" % (arguments.kfold, m), "output")
                    prettyPrint("Accuracy: %s" % str(metricsDict[m]["accuracy"]), "output")
                    prettyPrint("Recall: %s" % str(metricsDict[m]["recall"]), "output")
                    prettyPrint("Specificity: %s" % str(metricsDict[m]["specificity"]), "output")
                    prettyPrint("Precision: %s" % str(metricsDict[m]["precision"]), "output")
                    prettyPrint("F1 Score: %s" %  str(metricsDict[m]["f1score"]), "output")
                    # The average metrics for test dataset
                    prettyPrint("Metrics for test dataaset using %s-fold cross validation and %s" % (arguments.kfold, m), "output")
                    prettyPrint("Accuracy: %s" % str(metrics_testDict[m]["accuracy"]), "output")
                    prettyPrint("Recall: %s" % str(metrics_testDict[m]["recall"]), "output")
                    prettyPrint("Specificity: %s" % str(metrics_testDict[m]["specificity"]), "output")
                    prettyPrint("Precision: %s" % str(metrics_testDict[m]["precision"]), "output")
                    prettyPrint("F1 Score: %s" %  str(metrics_testDict[m]["f1score"]), "output")
                    # Log results to the outfile
                    tstamp = int(time.time())
                    outfile = arguments.outfile if arguments.outfile != "" else "./aion_%s.log" % tstamp
                    f = open(outfile, "a")
                    f.write("-----------------------------------------------\n")
                    f.write("| Metrics: iteration %s, timestamp: %s |\n" % (iteration-1, getTimestamp()))
                    f.write("-----------------------------------------------\n")
                    f.write("Validation - accuracy: %s, recall: %s, specificity: %s, precision: %s, F1-score: %s\n" % (metricsDict[m]["accuracy"], metricsDict[m]["recall"], metricsDict[m]["specificity"], metricsDict[m]["precision"], metricsDict[m]["f1score"]))
                    f.write("Test - accuracy: %s, recall: %s, specificity: %s, precision: %s, F1-score: %s\n" % (metrics_testDict[m]["accuracy"], metrics_testDict[m]["recall"], metrics_testDict[m]["specificity"], metrics_testDict[m]["precision"], metrics_testDict[m]["f1score"])) 
                    f.close()

            else:
                # Make sure the metrics are not empty
                if len(metrics) < 5 or len(metrics_test) < 5:
                    prettyPrint("FATAL: The recorded metrics are not complete. Exiting", "error")
                    print metrics, metrics_test
                    return False

                # The average metrics for training dataset
                prettyPrint("Metrics using %s-fold cross validation and %s" % (arguments.kfold, arguments.algorithm), "output")
                prettyPrint("Accuracy: %s" % str(metrics["accuracy"]), "output")
                prettyPrint("Recall: %s" % str(metrics["recall"]), "output")
                prettyPrint("Specificity: %s" % str(metrics["specificity"]), "output")
                prettyPrint("Precision: %s" % str(metrics["precision"]), "output")
                prettyPrint("F1 Score: %s" %  str(metrics["f1score"]), "output")
                # The average metrics for test dataset
                prettyPrint("Metrics for test dataaset using %s-fold cross validation and %s" % (arguments.kfold, arguments.algorithm), "output")
                prettyPrint("Accuracy: %s" % str(metrics_test["accuracy"]), "output")
                prettyPrint("Recall: %s" % str(metrics_test["recall"]), "output")
                prettyPrint("Specificity: %s" % str(metrics_test["specificity"]), "output")
                prettyPrint("Precision: %s" % str(metrics_test["precision"]), "output")
                prettyPrint("F1 Score: %s" %  str(metrics_test["f1score"]), "output")
                # Log results to the outfile
                outfile = arguments.outfile if arguments.outfile != "" else "./aion_%s.log" % arguments.vmname
                f = open(outfile, "a")
                f.write("-----------------------------------------------\n")
                f.write("| Metrics: iteration %s, timestamp: %s |\n" % (iteration-1, getTimestamp()))
                f.write("-----------------------------------------------\n")
                f.write("Validation - accuracy: %s, recall: %s, specificity: %s, precision: %s, F1-score: %s\n" % (metrics["accuracy"], metrics["recall"], metrics["specificity"], metrics["precision"], metrics["f1score"]))
                f.write("Test - accuracy: %s, recall: %s, specificity: %s, precision: %s, F1-score: %s\n" % (metrics_test["accuracy"], metrics_test["recall"], metrics_test["specificity"], metrics_test["precision"], metrics_test["f1score"])) 
                f.close()

            # Save incorrectly-classified training instances for re-analysis
            reanalyzeMalware, reanalyzeGoodware = [], [] # Reset the lists to store new misclassified instances
            for index in range(len(y)):
                if predicted[index] != y[index]:
                    if arguments.algorithm == "hmm":
                        if allTraceFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allTraceFiles[index])
                        else:
                            reanalyzeGoodware.append(allTraceFiles[index])
  
                    else:
                        # malware instances are in hashes whereas this appends their package names to the list. Update either!!
                        if allFeatureFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk"))
                        else:
                            reanalyzeGoodware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk"))

            print reanalyzeGoodware
            print reanalyzeMalware

            # Swapping metrics
            previousMetrics = currentMetrics
            currentMetrics = metrics

            # TODO: Restore snapshots of all VMs
            
        # Final Results
        prettyPrint("Training results after %s iterations" % iteration, "output")
        prettyPrint("Accuracy: %s" % currentMetrics["accuracy"], "output")
        prettyPrint("Recall: %s" % currentMetrics["recall"], "output")
        prettyPrint("Specificity: %s" % currentMetrics["specificity"], "output")
        prettyPrint("Precision: %s" % currentMetrics["precision"], "output")
        prettyPrint("F1 Score: %s" % currentMetrics["f1score"], "output")

    except Exception as e:
        prettyPrintError(e)
        return False
    
    prettyPrint("Good day to you ^_^")
    return True

if __name__ == "__main__":
    main() 
