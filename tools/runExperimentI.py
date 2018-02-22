#!/usr/bin/python

from Aion.data_generation.reconstruction import *
from Aion.data_inference.learning import HMM, ScikitLearners
from Aion.data_inference.extraction.featureExtraction import *
from Aion.utils.data import *     # Needed for accessing configuration files
from Aion.utils.graphics import * # Needed for pretty printing
from Aion.utils.misc import *
from Aion.utils.db import *
from Aion.shared.DroidutanTest import * # The Droidutan-driven test thread
from Aion.shared.DroidbotTest import * # The Droidbot-driven test thread

from sklearn.metrics import *
import numpy, ghmm
import introspy, hashlib # Used for analysis of introspy generated databases
from droidutan import Droidutan

import os, sys, glob, shutil, argparse, subprocess, sqlite3, time, threading, pickledb, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="runExperimentI.py", description="A tool to implement the stimulation-detection feedback loop using Garfield as stimulation engine.")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-d", "--datasetname", help="A unique name to give to the dataset used in the experiment (for DB storage purposes)", required=True)
    parser.add_argument("-r", "--runnumber", help="The number of the current run of the experiment (for DB storage purposes)", required=True)
    parser.add_argument("-f", "--analyzeapks", help="Whether to perform analysis on the retrieved APK's", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-t", "--analysistime", help="How long to run monkeyrunner (in seconds)", required=False, default=60)
    parser.add_argument("-u", "--analysisengine", help="The stimulation/analysis engine to use", required=False, choices=["droidbot", "droidutan"], default="droidutan")
    parser.add_argument("-v", "--vmnames", help="The name(s) of the Genymotion machine(s) to use for analysis (comma-separated)", required=False, default="")
    parser.add_argument("-z", "--vmsnapshots", help="The name(s) of the snapshot(s) to restore before analyzing an APK (comma-separated)", required=False, default="")
    parser.add_argument("-y", "--validation", help="Instructs Aion how to perform validation i.e. on 'training' or 'validation' datasets", required=True, choices=["training", "validation"])
    parser.add_argument("-k", "--kfold", help="Whether to use k-fold cross validation and the value of \"K\". Valid for 'validation' type of 'validation'", required=False, default=2)
    parser.add_argument("-s", "--selectkbest", help="Whether to select K best features from the ones extracted from the APK's", required=False, default=0)
    parser.add_argument("-e", "--featuretype", help="The type of features to consider during training", required=False, default="hybrid", choices=["static", "dynamic", "hybrid"])
    parser.add_argument("-p", "--fileextension", help="The extension of feature files", required=False, default="num")
    parser.add_argument("-m", "--accuracymargin", help="The margin (in percentage) within which the training accuracy is allowed to dip", required=False, default=1)
    parser.add_argument("-i", "--maxiterations", help="The maximum number of iterations to allow", required=False, default=25)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s dynamic experiment I")

        if arguments.vmnames == "":
            prettyPrint("No virtual machine names were supplied. Exiting", "warning")
            return False

        iteration = 1 # Initial values
        reanalysis = False
        appTraces = {}
        currentMetrics = {"accuracy": 0.0, "recall": 0.0, "specificity": 0.0, "precision": 0.0, "f1score": 0.0}
        previousMetrics = {"accuracy": -1.0, "recall": -1.0, "specificity": -1.0, "precision": -1.0, "f1score": -1.0}
        reanalyzeMalware, reanalyzeGoodware = [], [] # Use this as a cache until conversion
        allVMs = arguments.vmnames.split(',')
        allSnapshots = arguments.vmsnapshots.split(',')
        availableVMs = [] + allVMs # Initially

        # Initialize and populate database
        hashesDB = pickledb.load(getHashesDBPath(), True)
        aionDB = AionDB(int(arguments.runnumber), arguments.datasetname)
        algorithms = aionDB.select([], "learner", [])
        learners = {}
        for a in algorithms.fetchall():
            if len(a) > 1:
                learners[a[1].lower()] = str(a[0])

        # Load APK's and split into training and test datasets
        prettyPrint("Loading APK's from \"%s\" and \"%s\"" % (arguments.malwaredir, arguments.goodwaredir))
        # Retrieve malware APK's
        malAPKs = glob.glob("%s/*.apk" % arguments.malwaredir)
        if len(malAPKs) < 1:
            prettyPrint("Could not find any malicious APK's" , "warning")
        else:
            prettyPrint("Successfully retrieved %s malicious instances" % len(malAPKs))
        # Retrieve goodware APK's
        goodAPKs = glob.glob("%s/*.apk" % arguments.goodwaredir)
        if len(goodAPKs) < 1:
            prettyPrint("Could not find any benign APK's", "warning")
        else:
            prettyPrint("Successfully retrieved %s benign instances" % len(goodAPKs))

        # Split the data into training and test datasets
        malTraining, malTest = [], []
        goodTraining, goodTest = [], []
        malTestSize, goodTestSize = len(malAPKs) / 3, len(goodAPKs) / 3
        # Start with the malicious APKs
        while len(malTest) < malTestSize:
            malTest.append(malAPKs.pop(random.randint(0, len(malAPKs)-1)))
        malTraining += malAPKs
        prettyPrint("[MALWARE] Training dataset size is %s, test dataset size is %s" % (len(malTraining), len(malTest)))
        # Same with benign APKs
        while len(goodTest) < goodTestSize:
            goodTest.append(goodAPKs.pop(random.randint(0, len(goodAPKs)-1)))
        goodTraining += goodAPKs
        prettyPrint("[GOODWARE] Training dataset size is %s, test dataset size is %s" % (len(goodTraining), len(goodTest)))

        while (round(currentMetrics["f1score"] - previousMetrics["f1score"], 2) >= -(float(arguments.accuracymargin)/100.0)) and (iteration <= int(arguments.maxiterations)):
            # Set/update the reanalysis flag
            reanalysis = True if iteration > 1 else False
            prettyPrint("Experiment I: iteration #%s" % iteration, "info2")
            # Update the iteration number
            aionDB.update("run", [("runIterations", str(iteration))], [("runID", arguments.runnumber), ("runDataset", arguments.datasetname)]) # UPDATE run SET runIterations=X WHERE runID=[runnumber]
            if arguments.analyzeapks == "yes":
                allAPKs = malTraining + goodTraining + malTest + goodTest if not reanalysis else reanalyzeMalware + reanalyzeGoodware
                ########################
                ## Main Analysis Loop ##
                ########################
                currentProcesses = []
                while len(allAPKs) > 0:
                    prettyPrint("Starting analysis phase")
                    # Step 1. Pop an APK from "allAPKs" (Defaut: last element)
                    currentAPK = allAPKs.pop()
                    # Update the number of times an app has been stimulated
                    appPath = currentAPK[currentAPK.rfind("/")+1:] # Get the key
                    prettyPrint("Looking up the app \"%s\" in the hashes database" % appPath)
                    appName = hashesDB.get(appPath.lower().replace(".apk", ""))
                    if appName == None or appName == "":
                        appName = hashesDB.get(hashlib.sha256(appPath.lower()).hexdigest())
                    if appName == None or appName == "":
                        # We have to analyze the app
                        prettyPrint("Analyzing the app to retrieve package name", "warning")
                        apk, dx, vm = Droidutan.analyzeAPK(currentAPK)
                        appName = appPath.replace(".apk", "") if apk == None else apk.package  
                    prettyPrint("App name: %s" % appName)
                    # Update the database
                    # Does it already exist in the database
                    results = aionDB.select([], "app", [("appName", appName), ("appRunID", arguments.runnumber)])
                    rows = results.fetchall()
                    if len(rows) < 1:
                        appType = "malware" if currentAPK.lower().find("malware") != -1 else "goodware"
                        aionDB.insert("app", ["appName", "appType", "appRunID", "appRuns"], [appName, appType, arguments.runnumber,1])
                    else:
                        currentRuns = int(rows[0][3])
                        aionDB.update("app", [("appRuns", currentRuns+1)], [("appName", appName)])                                                                    
                    # Step 2. Check availability of VMs for test
                    while len(availableVMs) < 1:
                        prettyPrint("No AVD's available for analysis. Sleeping for 10 seconds")
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
                                if len(allAPKs) % 25 == 0: # TODO: How often to restore snapshot
                                    vm = p.name
                                    snapshot = allSnapshots[allVMs.index(vm)]
                                    prettyPrint("Restoring snapshot \"%s\" for AVD \"%s\"" % (snapshot, vm))
                                    restoreVirtualBoxSnapshot(vm, snapshot)

                            elif checkAVDState(p.name, "stopping")[0] or checkAVDState(p.name, "powered off")[0]:
                                prettyPrint("AVD \"%s\" is stuck. Forcing a restoration" % p.name, "warning")
                                vm = p.name
                                snapshot = allSnapshots[allVMs.index(vm)]
                                restoreVirtualBoxSnapshot(vm, snapshot)
                                          
                        print [p.name for p in currentProcesses]
                        print [p.is_alive() for p in currentProcesses]

                    # Step 3. Pop one VM from "availableVMs"
                    currentVM = availableVMs.pop()

                    if verboseON():
                        prettyPrint("Running \"%s\" on AVD \"%s\"" % (currentAPK, currentVM))

                    # Step 4. Start the analysis thread
                    pID = int(time.time())
                    if arguments.analysisengine == "droidutan":
                        p = DroidutanAnalysis(pID, currentVM, currentVM, currentAPK, int(arguments.analysistime))
                    elif arguments.analysisengine == "droidbot":
                        p = DroidbotAnalysis(pID, currentVM, currentVM, currentAPK, allSnapshots[allVMs.index(currentVM)], int(arguments.analysistime))
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

                
                #######################################
                ## Analyze log files  after analysis ##
                #######################################
                # Try to save some time by only analyzing apps that have been recently (re)analyzed
                allApps = malTraining + goodTraining + malTest + goodTest if not reanalysis else reanalyzeMalware + reanalyzeGoodware
                for app in allApps:
                    # 0. Retrieve the database file corresponding to the app
                    inFile = app.replace(".apk", "_filtered.log") if arguments.analysisengine == "droidutan" else app.replace(".apk", "_droidbot/logcat_filtered.log")

                    # 1. Check its existence
                    if not os.path.exists(inFile):
                        prettyPrint("Unable to find filtered log file: \"%s\". Skipping" % inFile, "warning")
                        continue

                    # 2. Extract and save numerical features
                    prettyPrint("Extracting %s features from APK" % arguments.featuretype)
                    staticFeatures, dynamicFeatures = [], []
                    # Save time in case of dynamic features
                    if arguments.featuretype == "static" or arguments.featuretype == "hybrid":
                        sfBasic, sfPermissions, sfAPI, staticFeatures = extractStaticFeatures(app)
                        prettyPrint("Successfully extracted %s static features" % len(staticFeatures))
                    if arguments.featuretype == "dynamic" or arguments.featuretype == "hybrid":
                        trace, dynamicFeatures = extractDroidmonFeatures(inFile)
                        prettyPrint("Successfully extracted %s dynamic features" % len(dynamicFeatures))
                        # Keeping track of trace changes
                        if app not in appTraces.keys():
                            appTraces[app] = []
                        appTraces[app].append((iteration, trace))

                    # 3. Store the features
                    if arguments.featuretype == "static" and len(staticFeatures) > 0:
                        features = staticFeatures
                    elif arguments.featuretype == "dynamic" and len(dynamicFeatures) > 0:
                        features = dynamicFeatures
                    elif arguments.featuretype == "hybrid" and len(staticFeatures) > 0 and len(dynamicFeatures) > 0:
                        features = staticFeatures + dynamicFeatures
                           
                    # 4. Write features to file
                    featuresFile = open(app.replace(".apk", ".%s" % arguments.fileextension), "w")
                    featuresFile.write("%s\n" % str(features))
                    featuresFile.close()
                    if arguments.featuretype == "hybrid":
                        featuresFile = open(app.replace(".apk", ".dyn"), "w")
                        featuresFile.write("%s\n" % str(dynamicFeatures))
                        featuresFile.close()

                    prettyPrint("Done analyzing \"%s\"" % inFile)

            ####################################################################
            # Load the JSON  and feature files as traces before classification #
            ####################################################################
            # Load numerical features
            allFeatureFiles = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.fileextension)) + glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.fileextension))
            if len(allFeatureFiles) < 1:
                prettyPrint("Could not retrieve any feature files. Exiting", "error")
                return False

            allDynamicFiles = glob.glob("%s/*.dyn" % arguments.malwaredir) + glob.glob("%s/*.dyn" % arguments.goodwaredir)
            if len(allDynamicFiles) < 1:
                prettyPRint("Could not retrieve any dynamic features files", "warning")

            prettyPrint("Retrieved %s feature files" % len(allFeatureFiles))
            # Split the loaded feature files as training and test 
            fileNames = open("filenames_run%s.txt" % arguments.runnumber, "w")
            Xtr, ytr, Xte, yte = [], [], [], []
            for ff in allFeatureFiles:
                fileName = ff.replace(".%s" % arguments.fileextension, ".apk")
                x = Numerical.loadNumericalFeatures(ff)
                if len(x) < 1:
                    prettyPrint("Empty feature vector returned. Skipping", "warning")
                    continue
                if fileName in malTraining:
                    Xtr.append(x)
                    ytr.append(1) 
                elif fileName in goodTraining:
                    Xtr.append(x)
                    ytr.append(0)
                elif fileName in malTest:
                    Xte.append(x)
                    yte.append(1)
                    fileNames.write("%s\n" % ff)
                elif fileName in goodTest:
                    Xte.append(x)
                    yte.append(0)
            fileNames.close()

            # Do the same for dynamic features
            if len(allDynamicFiles) > 1:
                prettyPrint("Processing %s dynamic features files" % len(allDynamicFiles))
                Xtrd, ytrd, Xted, yted = [], [], [], []
                for ff in allDynamicFiles:
                    fileName = ff.replace(".dyn", ".apk")
                    x = Numerical.loadNumericalFeatures(ff)
                    if len(x) < 1:
                        prettyPrint("Empty feature vector returned. Skipping", "warning")
                        continue
                    if fileName in malTraining:
                        Xtrd.append(x)
                        ytrd.append(1)
                    elif fileName in goodTraining:
                        Xtrd.append(x)
                        ytrd.append(0)
                    elif fileName in malTest:
                        Xted.append(x)
                        yted.append(1)
                    elif fileName in goodTest:
                        Xted.append(x)
                        yted.append(0)

            metricsDict, metricsDict_test = {}, {}
            dynamicDict, dynamicDict_test = {}, {}
            ####################################
            # Ensemble of learning algorithms #
            ###################################
            prettyPrint("Ensemble mode classification: K-NN, SVM, and Random Forests")
            statsFile = open("stats_run%s.csv" % arguments.runnumber, "w")
            predicted_trees100 = []
            # Classifying using K-nearest neighbors
            K = [10, 25, 50, 100, 250, 500]
            for k in K:
                prettyPrint("Classifying using K-nearest neighbors with K=%s" % k)
                clf, predicted, predicted_test = ScikitLearners.predictAndTestKNN(Xtr, ytr, Xte, yte, K=k, selectKBest=int(arguments.selectkbest))
                metrics = ScikitLearners.calculateMetrics(ytr, predicted)
                metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
                metricsDict["KNN%s" % k] = metrics
                metricsDict_test["KNN%s" % k] = metrics_test
                if arguments.featuretype == "hybrid" and len(allDynamicFiles) > 1:
                    # Same for dynamic features
                    prettyPrint("Classifying using K-nearest neighbors with K=%s and dynamic features" % k)
                    clf, predicted, predicted_test = ScikitLearners.predictAndTestKNN(Xtrd, ytr, Xted, yte, K=k, selectKBest=int(arguments.selectkbest))
                    metrics = ScikitLearners.calculateMetrics(ytr, predicted)
                    metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
                    dynamicDict["KNN%s" % k] = metrics
                    dynamicDict_test["KNN%s" % k] = metrics_test


            # Classifying using Random Forests
            E = [10, 25, 50, 75, 100]
            for e in E:
                prettyPrint("Classifying using Random Forests with %s estimators" % e)
                clf, predicted, predicted_test = ScikitLearners.predictAndTestRandomForest(Xtr, ytr, Xte, yte, estimators=e, selectKBest=int(arguments.selectkbest))
                if e == 100:
                    predicted_trees100 = [] + predicted_test.tolist()
                metrics = ScikitLearners.calculateMetrics(ytr, predicted)
                metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
                metricsDict["Trees%s" % e] = metrics
                metricsDict_test["Trees%s" % e] = metrics_test
                if arguments.featuretype == "hybrid" and len(allDynamicFiles) > 1:
                    # Same for dynamic features
                    prettyPrint("Classifying using Random Forests with %s estimators and dynamic features" % e)
                    clf, predicted, predicted_test = ScikitLearners.predictAndTestRandomForest(Xtrd, ytr, Xted, yte, estimators=e, selectKBest=int(arguments.selectkbest))
                    metrics = ScikitLearners.calculateMetrics(ytr, predicted)
                    metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
                    dynamicDict["Trees%s" % e] = metrics
                    dynamicDict_test["Trees%s" % e] = metrics_test

            # Classifying using SVM
            prettyPrint("Classifying using Support vector machines")
            clf, predicted, predicted_test = ScikitLearners.predictAndTestSVM(Xtr, ytr, Xte, yte, selectKBest=int(arguments.selectkbest))
            metrics = ScikitLearners.calculateMetrics(ytr, predicted)
            metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
            metricsDict["SVM"] = metrics
            metricsDict_test["SVM"] = metrics_test
            if arguments.featuretype == "hybrid" and len(allDynamicFiles) > 1:
                # Same for dynamic features
                prettyPrint("Classifying using Support vector machines and dunamic features")
                clf, predicted, predicted_test = ScikitLearners.predictAndTestSVM(Xtrd, ytr, Xted, yte, selectKBest=int(arguments.selectkbest))
                metrics = ScikitLearners.calculateMetrics(ytr, predicted)
                metrics_test = ScikitLearners.calculateMetrics(yte, predicted_test)
                dynamicDict["SVM"] = metrics
                dynamicDict_test["SVM"] = metrics_test

                
            # Now do the majority voting ensemble
            allCs = ["KNN-%s" % x for x in K] + ["FOREST-%s" % e for e in E] + ["SVM"]
            clf, predicted, predicted_test = ScikitLearners.predictAndTestEnsemble(Xtr, ytr, Xte, yte, classifiers=allCs, selectKBest=int(arguments.selectkbest))
            metrics = ScikitLearners.calculateMetrics(predicted, ytr) # Used to decide upon whether to iterate more
            metrics_test = ScikitLearners.calculateMetrics(predicted_test, yte)
            metricsDict["Ensemble"] = metrics
            metricsDict_test["Ensemble"] = metrics_test
            if arguments.featuretype == "hybrid" and len(allDynamicFiles) > 1:
                # Same for dynamic features
                clf, predicted, predicted_test = ScikitLearners.predictAndTestEnsemble(Xtrd, ytr, Xted, yte, classifiers=allCs, selectKBest=int(arguments.selectkbest))
                metrics = ScikitLearners.calculateMetrics(predicted, ytr) # Used to decide upon whether to iterate more
                metrics_test = ScikitLearners.calculateMetrics(predicted_test, yte)
                dynamicDict["Ensemble"] = metrics
                dynamicDict_test["Ensemble"] = metrics_test

      
            # Print and save results
            for m in metricsDict:
                # The average metrics for training dataset
                prettyPrint("Metrics using %s-fold cross validation and %s" % (arguments.kfold, m), "output")
                prettyPrint("Accuracy: %s" % str(metricsDict[m]["accuracy"]), "output")
                prettyPrint("Recall: %s" % str(metricsDict[m]["recall"]), "output")
                prettyPrint("Specificity: %s" % str(metricsDict[m]["specificity"]), "output")
                prettyPrint("Precision: %s" % str(metricsDict[m]["precision"]), "output")
                prettyPrint("F1 Score: %s" %  str(metricsDict[m]["f1score"]), "output")
                # Insert datapoint into the database
                learnerID = learners[m.lower()]                
                tstamp = getTimestamp(includeDate=True)#int(time.time()) 
                aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[learnerID, str(iteration), arguments.runnumber, tstamp, arguments.featuretype, "TRAIN", str(metricsDict[m]["accuracy"]), str(metricsDict[m]["recall"]), str(metricsDict[m]["specificity"]),str( metricsDict[m]["precision"]), str(metricsDict[m]["f1score"])])


            # Print and save results (Dynamic features)
            if arguments.featuretype == "hybrid" and len(allDynamicFiles) > 1:
                for d in dynamicDict:
                    # The average metrics for training dataset
                    prettyPrint("Metrics using %s-fold cross validation and %s and dynamic features" % (arguments.kfold, d), "output")
                    prettyPrint("Accuracy: %s" % str(dynamicDict[d]["accuracy"]), "output")
                    prettyPrint("Recall: %s" % str(dynamicDict[d]["recall"]), "output")
                    prettyPrint("Specificity: %s" % str(dynamicDict[d]["specificity"]), "output")
                    prettyPrint("Precision: %s" % str(dynamicDict[d]["precision"]), "output")
                    prettyPrint("F1 Score: %s" %  str(dynamicDict[d]["f1score"]), "output")
                    # Insert datapoint into the database
                    learnerID = learners[d.lower()]                
                    tstamp = getTimestamp(includeDate=True)#int(time.time()) 
                    aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[learnerID, str(iteration), arguments.runnumber, tstamp, "dynamic", "TRAIN", str(dynamicDict[d]["accuracy"]), str(dynamicDict[d]["recall"]), str(dynamicDict[d]["specificity"]),str(dynamicDict[d]["precision"]), str(dynamicDict[d]["f1score"])])

            # Save incorrectly-classified training instances for re-analysis
            reanalyzeMalware, reanalyzeGoodware = [], [] # Reset the lists to store new misclassified instances
            for index in range(len(ytr)):
                if predicted[index] != ytr[index]:
                    # malware instances are in hashes whereas this appends their package names to the list. Update either!!
                    if allFeatureFiles[index].find("malware") != -1:
                        reanalyzeMalware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk"))
                    else:
                        reanalyzeGoodware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk"))

            prettyPrint("Reanalyzing %s benign apps and %s malicious apps" % (len(reanalyzeGoodware), len(reanalyzeMalware)), "debug")

            # Swapping metrics
            previousMetrics = currentMetrics
            currentMetrics = metricsDict["Ensemble"]

            # Print and save results [FOR THE TEST DATASET]
            for m in metricsDict_test:
                # The average metrics for training dataset
                prettyPrint("Metrics using %s-fold cross validation and %s" % (arguments.kfold, m), "output")
                prettyPrint("Accuracy: %s" % str(metricsDict_test[m]["accuracy"]), "output")
                prettyPrint("Recall: %s" % str(metricsDict_test[m]["recall"]), "output")
                prettyPrint("Specificity: %s" % str(metricsDict_test[m]["specificity"]), "output")
                prettyPrint("Precision: %s" % str(metricsDict_test[m]["precision"]), "output")
                prettyPrint("F1 Score: %s" %  str(metricsDict_test[m]["f1score"]), "output")
                # Insert datapoint into the database
                learnerID = learners[m.lower()]                
                tstamp = getTimestamp(includeDate=True)#int(time.time()) 
                aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[learnerID, str(iteration), arguments.runnumber, tstamp, arguments.featuretype, "TEST", str(metricsDict_test[m]["accuracy"]), str(metricsDict_test[m]["recall"]), str(metricsDict_test[m]["specificity"]),str(metricsDict_test[m]["precision"]), str(metricsDict_test[m]["f1score"])])

            # Print and save results (Dynamic features)
            if arguments.featuretype == "hybrid" and len(allDynamicFiles) > 1:
                for d in dynamicDict_test:
                    # The average metrics for training dataset
                    prettyPrint("Metrics using %s-fold cross validation and %s and dynamic features" % (arguments.kfold, d), "output")
                    prettyPrint("Accuracy: %s" % str(dynamicDict_test[d]["accuracy"]), "output")
                    prettyPrint("Recall: %s" % str(dynamicDict_test[d]["recall"]), "output")
                    prettyPrint("Specificity: %s" % str(dynamicDict_test[d]["specificity"]), "output")
                    prettyPrint("Precision: %s" % str(dynamicDict_test[d]["precision"]), "output")
                    prettyPrint("F1 Score: %s" %  str(dynamicDict_test[d]["f1score"]), "output")
                    # Insert datapoint into the database
                    learnerID = learners[d.lower()]                
                    tstamp = getTimestamp(includeDate=True)#int(time.time()) 
                    aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[learnerID, str(iteration), arguments.runnumber, tstamp, "dynamic", "TEST", str(dynamicDict_test[d]["accuracy"]), str(dynamicDict_test[d]["recall"]), str(dynamicDict_test[d]["specificity"]),str(dynamicDict_test[d]["precision"]), str(dynamicDict_test[d]["f1score"])])

            # Commit results to the database
            aionDB.save()

            # Restore snapshots of all VMs
            vms, snaps = arguments.vmnames.split(','), arguments.vmsnapshots.split(',')
            if len(vms) > len(snaps):
                r = range(len(snaps))
            elif len(vms) < len(snaps):
                r = range(len(vms))
            else:
                r = range(len(vms)) # Or of snaps doesn't matter
            # Killall -9 VBoxHeadless
            doomsdayCmd = ["killall", "-9", "VBoxHeadless"]
            subprocess.Popen(doomsdayCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            for i in r:
                  prettyPrint("Restoring snapshot \"%s\" for AVD \"%s\"" % (snaps[i], vms[i]))
                  if restoreVirtualBoxSnapshot(vms[i], snaps[i]):
                      prettyPrint("Successfully restored AVD")
                  else:
                      prettyPrint("An error occurred while restoring the AVD")

            # Update the iteration number
            iteration += 1
            
        # Final Results
        prettyPrint("Training results after %s iterations" % str(iteration-1), "output")
        prettyPrint("Accuracy: %s" % currentMetrics["accuracy"], "output")
        prettyPrint("Recall: %s" % currentMetrics["recall"], "output")
        prettyPrint("Specificity: %s" % currentMetrics["specificity"], "output")
        prettyPrint("Precision: %s" % currentMetrics["precision"], "output")
        prettyPrint("F1 Score: %s" % currentMetrics["f1score"], "output")

        # Update the current run's end time
        aionDB.update("run", [("runEnd", getTimestamp(includeDate=True))], [("runID", arguments.runnumber)]) # UPDATE run SET runEnd=X WHERE runID=[runnumber]

        # Don't forget to save and close the Aion database
        aionDB.close()
 
        # Dump the traces dictionary to file
        f = open("experiment1_run%s_%s_traces.txt" % (arguments.runnumber, arguments.analysisengine), "w")
        f.write(str(appTraces))
        f.close()
        for index in range(len(predicted_trees100)):
            statsFile.write("%s,%s,%s,%s\n" % (Xte[index], yte[index], predicted_trees100[index], currentMetrics["recall"]))
        statsFile.close()

    except Exception as e:
        prettyPrintError(e)
        return False
    
    prettyPrint("Good day to you ^_^")
    return True

if __name__ == "__main__":
    main() 
