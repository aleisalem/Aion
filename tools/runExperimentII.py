#!/usr/bin/python

from Aion.data_generation.reconstruction import *
from Aion.data_generation.stimulation import *
from Aion.data_inference.learning import ScikitLearners
from Aion.data_inference.extraction.featureExtraction import *
from Aion.utils.data import *     # Needed for accessing configuration files
from Aion.utils.graphics import * # Needed for pretty printing
from Aion.utils.misc import *
from Aion.utils.db import *
from Aion.shared.DroidutanTest import * # The Droidutan-driven test thread
from Aion.shared.DroidbotTest import * # The Droidbot-driven test thread

from sklearn.metrics import *
import hashlib, pickle
from droidutan import Droidutan

import os, sys, glob, shutil, argparse, subprocess, sqlite3, time, threading, pickledb, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="runExperimentI.py", description="The second type of experiments of the Aion active learning framework.")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-d", "--datasetname", help="A unique name to give to the dataset used in the experiment (for DB storage purposes)", required=True)
    parser.add_argument("-r", "--runnumber", help="The number of the current run of the experiment (for DB storage purposes)", required=True)
    parser.add_argument("-f", "--analyzeapks", help="Whether to perform analysis on the retrieved APK's", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-t", "--analysistime", help="How long to run monkeyrunner (in seconds)", required=False, default=60)
    parser.add_argument("-u", "--analysisengine", help="The stimulation/analysis engine to use", required=False, choices=["droidbot", "droidutan"], default="droidutan")
    parser.add_argument("-v", "--vmnames", help="The name(s) of the Genymotion machine(s) to use for analysis (comma-separated)", required=False, default="")
    parser.add_argument("-z", "--vmsnapshots", help="The name(s) of the snapshot(s) to restore before analyzing an APK (comma-separated)", required=False, default="")
    parser.add_argument("-a", "--algorithm", help="The algorithm used to classify apps", required=False, default="Ensemble", choices=["KNN10", "KNN25", "KNN50", "KNN100", "KNN250", "KNN500", "SVM", "Trees25", "Trees50", "Trees75", "Trees100", "Ensemble"])
    parser.add_argument("-s", "--selectkbest", help="Whether to select K best features from the ones extracted from the APK's", required=False, default=0)
    parser.add_argument("-e", "--featuretype", help="The type of features to consider during training", required=False, default="hybrid", choices=["static", "dynamic", "hybrid"])
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
        currentMetrics = {"accuracy": 0.0, "recall": 0.0, "specificity": 0.0, "precision": 0.0, "f1score": 0.0}
        previousMetrics = {"accuracy": -1.0, "recall": -1.0, "specificity": -1.0, "precision": -1.0, "f1score": -1.0}
        reanalyzeMalware, reanalyzeGoodware = [], [] # Use this as a cache until conversion
        allVMs = arguments.vmnames.split(',')
        allSnapshots = arguments.vmsnapshots.split(',')
        availableVMs = [] + allVMs # Initially

        # Initialize and populate database
        hashesDB = pickledb.load(getHashesDBPath(), True)
        aionDB = AionDB(int(arguments.runnumber), arguments.datasetname)

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
                allAPKs = malTraining + goodTraining + malTest + goodTest if not reanalysis else reanalyzeMalware + reanalyzeGoodware + malTest + goodTest
                ########################
                ## Main Analysis Loop ##
                ########################
                currentProcesses = []
                while len(allAPKs) > 0:
                    prettyPrint("Starting analysis phase")
                    # Step 1. Pop an APK from "allAPKs" (Defaut: last element)
                    currentAPK = allAPKs.pop()
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
                                if len(allAPKs) % 25 == 0: # How often to restore snapshot?
                                    vm = p.name
                                    snapshot = allSnapshots[allVMs.index(vm)]
                                    prettyPrint("Restoring snapshot \"%s\" for AVD \"%s\"" % (snapshot, vm))
                                    restoreVirtualBoxSnapshot(vm, snapshot)

                            elif checkAVDState(p.name, "stopping")[0] or checkAVDState(p.name, "powered off")[0] or checkAVDState(p.name, "restoring snapshot")[0]:
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
                        if currentAPK in malTest+goodTest:
                            p = DroidutanAnalysis(pID, currentVM, currentVM, currentAPK, int(arguments.analysistime), currentAPK.replace(".apk", "_test_itn%s_filtered.log" % iteration))
                        else:
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
                allApps = malTraining + goodTraining + malTest + goodTest if not reanalysis else reanalyzeMalware + reanalyzeGoodware + malTest + goodTest
                for app in allApps:
                    # 0. Retrieve the database file corresponding to the app
                    if app in malTest+goodTest:
                        inFile = app.replace(".apk", "_test_itn%s_filtered.log" % iteration) # if arguments.analysisengine == "droidutan" else TODO
                    else:
                        inFile = app.replace(".apk", "_filtered.log") if arguments.analysisengine == "droidutan" else app.replace(".apk", "_droidbot/logcat_filtered.log")

                    # 1. Check its existence
                    if not os.path.exists(inFile):
                        prettyPrint("Unable to find filtered log file: \"%s\". Skipping" % inFile, "warning")
                        continue

                    # 2. Extract and save numerical features
                    prettyPrint("Extracting %s features from APK \"%s\"" % (arguments.featuretype, inFile))
                    staticFeatures, dynamicFeatures = [], []
                    # Save time in case of dynamic features
                    if arguments.featuretype == "static" or arguments.featuretype == "hybrid":
                        sfBasic, sfPermissions, sfAPI, staticFeatures = extractStaticFeatures(app)
                        prettyPrint("Successfully extracted %s static features" % len(staticFeatures))
                    if arguments.featuretype == "dynamic" or arguments.featuretype == "hybrid":
                        trace, dynamicFeatures = extractDroidmonFeatures(inFile)
                        prettyPrint("Successfully extracted %s dynamic features" % len(dynamicFeatures))

                    # 3. Store the features
                    if arguments.featuretype == "static" and len(staticFeatures) > 0:
                        features = staticFeatures
                    elif arguments.featuretype == "dynamic" and len(dynamicFeatures) > 0:
                        features = dynamicFeatures
                    elif arguments.featuretype == "hybrid" and len(staticFeatures) > 0 and len(dynamicFeatures) > 0:
                        features = staticFeatures + dynamicFeatures
                           
                    # 4. Write features to file
                    if app in malTest+goodTest:
                        featuresFile = open(app.replace(".apk", "_test_itn%s.%s" % (iteration, arguments.featuretype)), "w")
                    else:
                        featuresFile = open(app.replace(".apk", ".%s" % arguments.featuretype), "w")
                    featuresFile.write("%s\n" % str(features))
                    featuresFile.close()
                    prettyPrint("Done analyzing \"%s\"" % inFile)

            ####################################################################
            # Load the JSON  and feature files as traces before classification #
            ####################################################################
            # Load numerical features
            allFeatureFiles = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.featuretype)) + glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.featuretype))
            if len(allFeatureFiles) < 1:
                prettyPrint("Could not retrieve any feature files. Exiting", "error")
                return False

            prettyPrint("Retrieved %s feature files" % len(allFeatureFiles))
            # Split the loaded feature files as training and test 
            Xtr, ytr = [], []
            for ff in allFeatureFiles:
                fileName = ff.replace(".%s" % arguments.featuretype, ".apk")
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


            metricsDict = {}
            ############
            # Training #
            ############
            # Classifying using [algorithm]
            prettyPrint("Classifying using %s" % arguments.algorithm)
            clfFile = "%s/db/%s_run%s_itn%s_%s.txt" % (getProjectDir(), arguments.algorithm, arguments.runnumber, iteration, arguments.featuretype)
            # Train and predict
            if arguments.algorithm.lower().find("trees") != -1:
                e = int(arguments.algorithm.replace("Trees", ""))
                clf, predicted, predicted_test = ScikitLearners.predictAndTestRandomForest(Xtr, ytr, estimators=e, selectKBest=int(arguments.selectkbest))
            elif arguments.algorithm.lower().find("knn") != -1:
                k = int(arguments.algorithm.replace("KNN", ""))
                clf, predicted, predicted_test = ScikitLearners.predictAndTestKNN(Xtr, ytr, K=k, selectKBest=int(arguments.selectkbest))
            elif arguments.algorithm.lower().find("svm") != -1:
                clf, predicted, predicted_test = ScikitLearners.predictAndTestSVM(Xtr, ytr, selectKBest=int(arguments.selectkbest))
            else:
                K = [10, 25, 50, 100, 250, 500]
                E = [10, 25, 50, 75, 100]
                allCs = ["KNN-%s" % k for k in K] + ["FOREST-%s" % e for e in E] + ["SVM"]
                clf, predicted, predicted_test = ScikitLearners.predictAndTestEnsemble(Xtr, ytr, classifiers=allCs, selectKBest=int(arguments.selectkbest))
            # Write to file
            open(clfFile, "w").write(pickle.dumps(clf))
            metrics = ScikitLearners.calculateMetrics(ytr, predicted)
            metricsDict = metrics

            # Print and save results
            prettyPrint("Metrics using %s at iteration %s" % (arguments.algorithm, iteration), "output")
            prettyPrint("Accuracy: %s" % str(metricsDict["accuracy"]), "output")
            prettyPrint("Recall: %s" % str(metricsDict["recall"]), "output")
            prettyPrint("Specificity: %s" % str(metricsDict["specificity"]), "output")
            prettyPrint("Precision: %s" % str(metricsDict["precision"]), "output")
            prettyPrint("F1 Score: %s" %  str(metricsDict["f1score"]), "output")
            # Insert datapoint into the database
            tstamp = getTimestamp(includeDate=True)
            learnerID = "%s_run%s_itn%s" % (arguments.algorithm, arguments.runnumber, iteration)
            aionDB.insert(table="learner", columns=["lrnID", "lrnParams"], values=[learnerID, clfFile])
            aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[learnerID, str(iteration), arguments.runnumber, tstamp, arguments.featuretype, "TRAIN", str(metricsDict["accuracy"]), str(metricsDict["recall"]), str(metricsDict["specificity"]), str(metricsDict["precision"]), str(metricsDict["f1score"])])

            # Save incorrectly-classified training instances for re-analysis
            reanalyzeMalware, reanalyzeGoodware = [], [] # Reset the lists to store new misclassified instances
            for index in range(len(ytr)):
                if predicted[index] != ytr[index]:
                    if allFeatureFiles[index].find("test") != -1:
                        prettyPrint("Skipping adding test file \"%s\" to the reanalysis lists" %  allFeatureFiles[index])
                    else:
                        # Add to reanalysis lists
                        if allFeatureFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allFeatureFiles[index].replace(arguments.featuretype, "apk"))
                        else:
                            reanalyzeGoodware.append(allFeatureFiles[index].replace(arguments.featuretype, "apk"))

            prettyPrint("Reanalyzing %s benign and %s malicious training apps" % (len(reanalyzeGoodware), len(reanalyzeMalware)), "debug")

            # Swapping metrics
            previousMetrics = currentMetrics
            currentMetrics = metricsDict

            # Commit results to the database
            aionDB.save()

            # Restore snapshots of all VMs
            vms, snaps = arguments.vmnames.split(','), arguments.vmsnapshots.split(',')
            if len(vms) > len(snaps):
                r = range(len(snaps))
            else:
                r = range(len(vms)) # Or of snaps doesn't matter
            # Killall -9 VBoxHeadless
            #doomsdayCmd = ["killall", "-9", "VBoxHeadless"]
            doomsdayCmd = ["killall", "-9", "VBoxSVC"]
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

        #######################################################
        # Commence the test phase using the "best classifier" #
        #######################################################
        # 1. Retrieve the best classifier and its iteration (X)
        results = aionDB.execute("SELECT * FROM datapoint WHERE dpRun='%s' AND dpFeature='%s' ORDER BY dpFScore DESC" % (arguments.runnumber, arguments.featuretype))
        if not results:
            prettyPrint("Could not retrieve data about the training phase. Exiting", "error")
            aionDB.close()
            return False

        data = results.fetchall()
        if len(data) < 1:
            prettyPrint("Could not retrieve data about the training phase. Exiting", "error")
            aionDB.close()
            return False
        
        # 1.a. Best classifier should be the first entry
        bestClassifier, bestItn, bestF1score, bestSp = data[0][1], data[0][2], data[0][11], data[0][9]
        if verboseON():
            prettyPrint("The best classifier is %s at iteration %s with F1score of %s and Specificity score of %s" % (bestClassifier, bestItn, bestF1score, bestSp), "debug")
        # 1.b. Load classifier from hyper parameters file
        results = aionDB.execute("SELECT * FROM learner WHERE lrnID='%s'" % bestClassifier)
        if not results:
            prettyPrint("Could not find the hyperparameters file for \"%s\". Exiting" % bestClassifier, "error")
            aionDB.close()
            return False

        data = results.fetchall()
        if len(data) < 1:
            prettyPrint("Could not find the hyperparameters file for \"%s\". Exiting" % bestClassifier, "error")
            aionDB.close()
            return False

        clfFile = data[0][1]
        if not os.path.exists(clfFile):
            prettyPrint("The file \"%s\" does not exist. Exiting" % clfFile, "error")
            aionDB.close()
            return False
 
        prettyPrint("Loading classifier \"%s\" from \"%s\"" % (bestClassifier, clfFile))
        clf = pickle.loads(open(clfFile).read())

        # 2. Classify feature vectors
        P, N = 0.0, 0.0
        TP_maj, TN_maj, FP_maj, FN_maj = 0.0, 0.0, 0.0, 0.0 # To keep track of majority vote classification
        TP_one, TN_one, FP_one, FN_one = 0.0, 0.0, 0.0, 0.0 # To keep track of one-instance classification
        for app in malTest + goodTest:
            prettyPrint("Processing test app \"%s\"" % app)
            # 2.a.  Retrieve all feature vectors up to [iteration]
            appVectors = {}
            for i in range(1, bestItn+1):
                 if os.path.exists(app.replace(".apk", "_test_itn%s.%s" % (i, arguments.featuretype))):
                     v = Numerical.loadNumericalFeatures(app.replace(".apk", "_test_itn%s.%s" % (i, arguments.featuretype)))
                     if len(v) > 1:
                         appVectors["itn%s" % i] = v

            if len(appVectors) < 1:
                prettyPrint("Could not retrieve any feature vectors. Skipping", "warning")
                continue
               
            prettyPrint("Successfully retrieved %s feature vectors of type \"%s\"" % (len(appVectors), arguments.featuretype))
            # 2.b. Classify each feature vector using the loaded classifier
            appLabel = 1 if app in malTest else 0
            if appLabel == 1:
                P += 1.0
            else:
                N += 1.0
            labels = ["Benign", "Malicious"]
            appMalicious, appBenign = 0.0, 0.0
            for v in appVectors:
                predictedLabel = clf.predict(appVectors[v]).tolist()[0]
                prettyPrint("\"%s\" app was classified as \"%s\" according to iteration %s" % (labels[appLabel], labels[predictedLabel], v.replace("itn", "")), "output")
                classifiedCorrectly = "YES" if labels[appLabel] == labels[predictedLabel] else "NO"
                aionDB.insert("testapp", ["taName", "taRun", "taIteration", "taType", "taClassified", "taLog"], [app, arguments.runnumber, v.replace("itn", ""), labels[appLabel], classifiedCorrectly, app.replace(".apk", "_test_%s_filtered.log" % v)])
                if predictedLabel == 1:
                    appMalicious += 1.0
                else:
                    appBenign += 1.0

            # 2.c. Decide upon the app's label according to majority vote vs. one-instance
            majorityLabel = 1 if (appMalicious/float(len(appVectors))) >= 0.5 else 0
            oneLabel = 1 if appMalicious >= 1.0 else 0
            if appLabel == 1:
                # Malicious app
                if majorityLabel == 1:
                    TP_maj += 1.0
                else:
                    FN_maj += 1.0
                if oneLabel == 1:
                    TP_one += 1.0
                else:
                    FN_one += 1.0
            else:
                # Benign app
                if majorityLabel == 1:
                    FP_maj += 1.0
                else:
                    TN_maj += 1.0
                if oneLabel == 1:
                    FP_one += 1.0
                else:
                    TN_one += 1.0
            # 2.d. Declare the classification of the app in question
            prettyPrint("\"%s\" app has been declared as \"%s\" by majority vote and as \"%s\" by one-instance votes" % (labels[appLabel], labels[majorityLabel], labels[oneLabel]), "output")

        # 3. Calculate metrics
        accuracy_maj, accuracy_one = (TP_maj+TN_maj)/(P+N), (TP_one+TN_one)/(P+N)
        recall_maj, recall_one = TP_maj/P, TP_one/P
        specificity_maj, specificity_one = TN_maj/N, TN_one/N
        precision_maj, precision_one = TP_maj/(TP_maj+FP_maj), TP_one/(TP_one+FP_one)
        f1score_maj, f1score_one = 2 * (precision_maj*recall_maj) / (precision_maj+recall_maj), 2 * (precision_one*recall_one) / (precision_one+recall_one)

        # 4. Display and store metrics
        prettyPrint("Test metrics using %s at run %s" % (arguments.algorithm, arguments.runnumber), "output")
        prettyPrint("Accuracy (majority): %s versus accuracy (one-instance): %s" % (str(accuracy_maj), str(accuracy_one)), "output")
        prettyPrint("Recall (majority): %s versus recall (one-instance): %s" % (str(recall_maj), str(recall_one)), "output")
        prettyPrint("Specificity (majority): %s versus specificity (one-instance): %s" % (str(specificity_maj), str(specificity_one)), "output")
        prettyPrint("Precision (majority): %s versus precision (one-instance): %s" % (str(precision_maj), str(precision_one)), "output")
        prettyPrint("F1 Score (majority): %s versus F1 score (one-instance): %s" % (str(f1score_maj), str(f1score_one)), "output")
        
        # 4.b. Store in the database
        aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[bestClassifier, bestItn, arguments.runnumber, tstamp, arguments.featuretype, "TEST:Maj", accuracy_maj, recall_maj, specificity_maj, precision_maj, f1score_maj])
        # Same for one-instance classification scheme
        aionDB.insert(table="datapoint", columns=["dpLearner", "dpIteration", "dpRun", "dpTimestamp", "dpFeature", "dpType", "dpAccuracy", "dpRecall", "dpSpecificity", "dpPrecision", "dpFscore"], values=[bestClassifier, bestItn, arguments.runnumber, tstamp, arguments.featuretype, "TEST:One", accuracy_one, recall_one, specificity_one, precision_one, f1score_one])

        # Don't forget to save and close the Aion database
        aionDB.close()

        # Send notification email
        subject = "Run %s on %s Successful" % (arguments.runnumber, arguments.datasetname)
        msg = "Achieved results:\nTest F1 score (majority): %s versus F1 score (one-instance): %s\nTest Specificity (majority): %s versus specificity (one-instance): %s" % (str(f1score_maj), str(f1score_one), str(specificity_maj), str(specificity_one))
        sendEmail("alu-precision", getAdminEmail(), subject, msg)

    except Exception as e:
        prettyPrintError(e)
        subject = "Run %s on %s failed!!" % (arguments.runnumber, arguments.datasetname)
        msg = "Error: %s" % e
        sendEmail("alu-precision", getAdminEmail(), subject, msg)

        return False
    
    prettyPrint("Good day to you ^_^")
    return True

if __name__ == "__main__":
    main() 
