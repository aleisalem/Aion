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
    parser.add_argument("-a", "--algorithm", help="The machine learning algorithm to use for classification", required=True, choices=["trees", "svm"])
    parser.add_argument("-k", "--kfold", help="Whether to use k-fold cross validation and the value of \"K\"", required=False, default=2)
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
                while len(allAPKs) > 0:

                    # Step 1. Pop an APK from "allAPKs" (Defaut: last element)
                    currentAPK = allAPKs.pop()

                    # Ignore previously-analyzed APK's that are not in for re-analysis
                    if not reanalysis:
                        if os.path.exists(currentAPK.replace(".apk", ".%s" % arguments.fileextension)):
                            # Second line of defense
                            if not currentAPK in reanalyzeMalware + reanalyzeGoodware:
                                prettyPrint("APK \"%s\" has been analyzed before. Skipping" % currentAPK, "warning")
                                continue

                    # Step 2. Check availability of VMs for test
                    while len(availableVMs) < 1:
                        prettyPrint("No AVD's available for analysis. Sleeping for %s seconds" % arguments.analysistime)
                        # 2.a. Sleep for "analysisTime"
                        time.sleep(int(arguments.analysistime))
                        # 2.b. Check for available machines
                        currentThreads = [t.name for t in threading.enumerate()]
                        for v in allVMs:
                            if v not in currentThreads:
                                availableVMs.append(v)

                    # Step 3. Pop one VM from "availableVMs"
                    currentVM = availableVMs.pop()

                    if verboseON():
                        prettyPrint("Running \"%s\" on AVD \"%s\"" % (currentAPK, currentVM))

                    # Step 4. Start the analysis thread
                    tID = int(time.time())
                    t = DroidutanAnalysis(tID, currentVM, (currentVM, ), currentAPK, int(arguments.analysistime))
                    t.start()
                      
                    prettyPrint("%s APKs left to analyze" % len(allAPKs), "output")
    

                # Just make sure all VMs are done
                while len(availableVMs) < len(allVMs):
                    prettyPrint("Waiting for AVD's to complete analysis")
                    time.sleep(int(arguments.analysistime))
                    currentThreads = [t.name for t in threading.enumerate()]
                    for v in allVMs:
                        if v not in currentThreads:
                            availableVMs.append(v)

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
                    staticFeatures, dynamicFeatures = extractAndroguardFeatures(dbFile.replace(".db", ".apk")), extractIntrospyFeatures(jsonTraceFile.name)
                    if len(staticFeatures) < 1 or len(dynamicFeatures) < 1:
                        prettyPrint("An error occurred while extracting static or dynamic features. Skipping", "warning")
                        continue
                    # Otherwise, store the features
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
                    os.remove(dbFile)
 
                    # Shutdown the genymotion machine
                    #subprocess.call(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    #genyProcess.kill() # Second line of defense

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
                        
                     
                    predicted, predicted_test = ScikitLearners.predictedAndTestKFoldSVMSSK(X, y, Xtest, ytest, kfold=int(arguments.kfold), subseqLength=int(arguments.svmsubsequence))

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

                    predicted, predicted_test = ScikitLearners.predictAndTestKFoldSVM(X, y, Xtest, ytest, kfold=int(arguments.kfold))

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

                predicted, predicted_test = ScikitLearners.predictAndTestKFoldTree(X, y, Xtest, ytest, kfold=int(arguments.kfold))
                metrics, metrics_test = ScikitLearners.calculateMetrics(y, predicted), ScikitLearners.calculateMetrics(ytest, predicted_test)
                
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
