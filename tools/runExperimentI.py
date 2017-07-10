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
                malAPKs = reanalyzeMalware if reanalysis else glob.glob("%s/*.apk" % arguments.malwaredir)
                if len(malAPKs) < 1:
                    prettyPrint("Could not find any malicious APK's" , "warning")
                else:
                    prettyPrint("Successfully retrieved %s malicious instances" % len(malAPKs))
                # Retrieve goodware APK's
                goodAPKs = reanalyzeGoodware if reanalysis else glob.glob("%s/*.apk" % arguments.goodwaredir)
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
                                # Also restore clean state of machine 
                                if len(allAPKs) % 10 == 0:
                                    vm = p.name
                                    snapshot = allSnapshots[allVMs.index(vm)]
                                    prettyPrint("Restoring snapshot \"%s\" for AVD \"%s\"" % (snapshot, vm))
                                    restoreVirtualBoxSnapshot(vm, snapshot)
                                          
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
                    sfBasic, sfPermissions, sfAPI, staticFeatures = extractStaticFeatures(dbFile.replace(".db", ".apk"))
                    dynamicFeatures = extractIntrospyFeatures(jsonTraceFile.name)
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
            allTraceFiles = glob.glob("%s/*.json" % arguments.malwaredir) + glob.glob("%s/*.json" % arguments.goodwaredir)
               
            prettyPrint("Retrieved %s feature files and %s trace files" % (len(allFeatureFiles), len(allTraceFiles)))
 
            metrics = {}
            
            ###########################
            # Support Vector Machines #
            ###########################
            if arguments.algorithm == "svm":
                prettyPrint("Classifying using Support Vector Machines")
                X, y = [], []
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
                     
                    predicted = ScikitLearners.predictedKFoldSVMSSK(X, y, kfold=int(arguments.kfold), subseqLength=int(arguments.svmsubsequence), selectKBest=int(arguments.selectKBest))

                else:
                    # Loading training feature vectors
                    for f in allFeatureFiles:
                        X.append(Numerical.loadNumericalFeatures(f))
                        # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                        if f.find("malware") != -1:
                            y.append(1)
                        else:
                            y.append(0)

                    predicted = ScikitLearners.predictKFoldSVM(X, y, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))

                metrics = ScikitLearners.calculateMetrics(y, predicted)

            ##################
            # Decision Trees #
            ##################
            elif arguments.algorithm == "tree":
                prettyPrint("Classifying using Decision Trees")
                X, y = [], []
                # Loading training feature vectors
                for f in allFeatureFiles:
                    X.append(Numerical.loadNumericalFeatures(f))
                    # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                    if f.find("malware") != -1:
                        y.append(1)
                    else:
                        y.append(0)

                predicted = ScikitLearners.predictKFoldTrees(X, y, kfold=int(arguments.kfold), selectKBest=int(arguments.selectKBest))
                metrics = ScikitLearners.calculateMetrics(y, predicted)

            ####################################
            # Ensemble of learning algorithms #
            ###################################
            elif arguments.algorithm == "ensemble":
                prettyPrint("Ensemble mode classification: K-NN, SVM, and Random Forests")
                X, y = [], []
                # Loading training feature vectors
                for f in allFeatureFiles:
                    X.append(Numerical.loadNumericalFeatures(f))
                    # TODO: Assumes the word "malware" is in the file path/name. Fix that.
                    if f.find("malware") != -1:
                        y.append(1)
                    else:
                        y.append(0)

                # Classifying using K-nearest neighbors
                K = [10, 25, 50, 100, 250, 500]
                metricsDict = {}
                tmpPredicted = [0]*len(y)
                for k in K:
                    prettyPrint("Classifying using K-nearest neighbors with K=%s" % k)
                    predicted = ScikitLearners.predictKFoldKNN(X, y, K=k, kfold=int(arguments.kfold), selectKBest=int(arguments.selectkbest))

                    for i in range(len(predicted)):
                        tmpPredicted[i] += predicted[i]

                    metrics = ScikitLearners.calculateMetrics(y, predicted)
                    metricsDict["KNN%s" % k] = metrics

                # Classifying using Random Forests
                E = [10, 25, 50, 75, 100]
                for e in E:
                    prettyPrint("Classifying using Random Forests with %s estimators" % e)
                    predicted = ScikitLearners.predictKFoldTrees(X, y, kfold=int(arguments.kfold), selectKBest=int(arguments.selectkbest))

                    for i in range(len(predicted)):
                        tmpPredicted[i] += predicted[i]

                    metrics = ScikitLearners.calculateMetrics(y, predicted)
                    metricsDict["Trees%s" % e] = metrics

                # Classifying using SVM
                prettyPrint("Classifying using Support vector machines")
                predicted = ScikitLearners.predictKFoldSVM(X, y, kfold=int(arguments.kfold), selectKBest=int(arguments.selectkbest))

                for i in range(len(predicted)):
                    tmpPredicted[i] += predicted[i]

                metrics = ScikitLearners.calculateMetrics(y, predicted)
                metricsDict["svm"] = metrics
                
                # Average the predictions in tempPredicted
                predicted = [-1]*len(y)
                for i in range(len(tmpPredicted)):
                    predicted[i] = 1 if tmpPredicted[i] >= 12.0/2.0 else 0 # 12 classifiers

                metricsDict["all"] = ScikitLearners.calculateMetrics(predicted, y)
                metrics = metricsDict["all"] # Used to decide upon whether to iterate more
      
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
                    # Log results to the outfile
                    tstamp = int(time.time())
                    outfile = arguments.outfile if arguments.outfile != "" else "./aion_%s.log" % tstamp
                    f = open(outfile, "a")
                    f.write("############################################################################\n")
                    f.write("# Metrics: algorithm: %s, iteration %s, timestamp: %s #\n" % (m, iteration-1, getTimestamp()))
                    f.write("############################################################################\n")
                    f.write("Validation - accuracy: %s, recall: %s, specificity: %s, precision: %s, F1-score: %s\n" % (metricsDict[m]["accuracy"], metricsDict[m]["recall"], metricsDict[m]["specificity"], metricsDict[m]["precision"], metricsDict[m]["f1score"]))
                    f.close()

            else:
                # Make sure the metrics are not empty
                if len(metrics) < 5:
                    prettyPrint("FATAL: The recorded metrics are not complete. Exiting", "error")
                    print metrics
                    return False

                # The average metrics for training dataset
                prettyPrint("Metrics using %s-fold cross validation and %s" % (arguments.kfold, arguments.algorithm), "output")
                prettyPrint("Accuracy: %s" % str(metrics["accuracy"]), "output")
                prettyPrint("Recall: %s" % str(metrics["recall"]), "output")
                prettyPrint("Specificity: %s" % str(metrics["specificity"]), "output")
                prettyPrint("Precision: %s" % str(metrics["precision"]), "output")
                prettyPrint("F1 Score: %s" %  str(metrics["f1score"]), "output")
                # Log results to the outfile
                outfile = arguments.outfile if arguments.outfile != "" else "./aion_%s.log" % arguments.vmname
                f = open(outfile, "a")
                f.write("-----------------------------------------------\n")
                f.write("| Metrics: iteration %s, timestamp: %s |\n" % (iteration-1, getTimestamp()))
                f.write("-----------------------------------------------\n")
                f.write("Validation - accuracy: %s, recall: %s, specificity: %s, precision: %s, F1-score: %s\n" % (metrics["accuracy"], metrics["recall"], metrics["specificity"], metrics["precision"], metrics["f1score"]))
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
            vms, snaps = arguments.vmnames.split(','), arguments.vmsnapshots.split(',')
            if len(vms) > len(snaps):
                r = range(len(snaps))
            elif len(vms) < len(snaps):
                r = range(len(vms))
            else:
                r = range(len(vms)) # Or of snaps doesn't matter
            for i in r:
                  prettyPrint("Restoring snapshot \"%s\" for AVD \"%s\"" % (snaps[i], vms[i]))
                  if restoreVirtualBoxSnapshot(vms[i], snaps[i]):
                      prettyPrint("Successfully restored AVD")
                  else:
                      prettyPrint("An error occurred while restoring the AVD")
            
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
