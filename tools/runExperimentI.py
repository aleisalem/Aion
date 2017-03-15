#!/usr/bin/python

from Aion.data_generation.stimulation.Garfield import Garfield
from Aion.data_generation.reconstruction import *
from Aion.data_inference.learning import HMM, ScikitLearners
from Aion.data_inference.extraction.featureExtraction import *
from Aion.utils.data import *     # Needed for accessing configuration files
from Aion.utils.graphics import * # Needed for pretty printing
from Aion.utils.misc import *

from sklearn.metrics import *
import numpy, ghmm
import introspy # Used for analysis of introspy generated databases

import os, sys, glob, shutil, argparse, subprocess, sqlite3



def defineArguments():
    parser = argparse.ArgumentParser(prog="runExperimentI.py", description="A tool to implement the stimulation-detection feedback loop using Garfield as stimulation engine.")
    parser.add_argument("-s", "--sdkdir", help="The path to Android SDK", required=True)
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign APK's to analyze and use as training/validation dataset", required=True)
    parser.add_argument("-m", "--malwaredirtest", help="The directory containing the malicious APK's to analyze and use as test dataset", required=True)
    parser.add_argument("-b", "--goodwaredirtest", help="The directory containing the benign APK's to analyze and use as test dataset .", required=True)  
    parser.add_argument("-f", "--analyzeapks", help="Whether to perform analysis on the retrieved APK's", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-t", "--analysistime", help="How long to run monkeyrunner (in seconds)", required=False, default=60)
    parser.add_argument("-v", "--vmname", help="The name of the Genymotion machine to use for analysis", required=False, default="")
    parser.add_argument("-z", "--vmsnapshot", help="The name of the snapshot to restore before analyzing an APK", required=False, default="")
    parser.add_argument("-a", "--algorithm", help="The machine learning algorithm to use for classification", required=False, default="hmm", choices=["hmm", "associative", "svm"])
    parser.add_argument("-k", "--kfold", help="Whether to use k-fold cross validation and the value of \"K\"", required=False, default=2)
    parser.add_argument("-p", "--fileextension", help="The extension of feature files", required=False, default="txt")
    parser.add_argument("-u", "--svmusessk", help="Whether to use the SSK kernel with SVM", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-n", "--svmsubsequence", help="The length of the subsequence to consider upon using SVM's with the SSK", required=False, default=3)
    parser.add_argument("-w", "--hmmtrainwith", help="Whether to train the HMM with malicious or benign instances", required=False, default="malware", choices=["malware", "goodware"])
    parser.add_argument("-l", "--hmmtracelength", help="The maximum trace length to consider during testing", required=False, default=50)
    parser.add_argument("-e", "--hmmthreshold", help="The likelihood threshold to apply during testing", required=False, default=-500)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s experiment I")

        # Some sanity checks
        if not os.path.exists(arguments.sdkdir):
             prettyPrint("Unable to locate the Android SDK. Exiting", "error")
             return False
 
        iteration = 1 # Initial values
        reanalysis = False
        currentMetrics = {"accuracy": 0.0, "recall": 0.0, "specificity": 0.0, "precision": 0.0, "f1score": 0.0}
        previousMetrics = {"accuracy": -1.0, "recall": -1.0, "specificity": -1.0, "precision": -1.0, "f1score": -1.0}
        reanalyzeMalware, reanalyzeGoodware = [], [] # Use this as a cache until conversion

        while currentMetrics["f1score"] > previousMetrics["f1score"]:
            reanalysis = True if iteration > 1 else False
            prettyPrint("Experiment I: iteration #%s" % iteration, "info2")
            iteration += 1
            if arguments.analyzeapks == "yes":
                # Define paths to Android SDK tools
                monkeyRunnerPath = arguments.sdkdir + "/tools/bin/monkeyrunner"
                adbPath = arguments.sdkdir + "/platform-tools/adb"

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

                genyProcess = None # A (dummy) handle to the genymotion player process
                for path in allAPKs:
                    # 0. Check whether the app has already been analyzed
                    if arguments.algorithm == "svm" or arguments.algorithm == "tree":
                        if os.path.exists(path.replace("apk", arguments.fileextension)):
                            prettyPrint("App has already been analyzed. Skipping", "warning")
                            continue
                    else:
                        if os.path.exists(path.replace(".apk", ".json")):
                            prettyPrint("App has already been analyzed. Skipping", "warning")
                            continue
                        
                    # 1. Statically analyze the APK using androguard
                    APKType = "malware" if path in malAPKs else "goodware"
                    currentAPK = Garfield(path, APKType)
 
                    if verboseON():
                        prettyPrint("Analyzing APK: \"%s\"" % path, "debug")

                    # 1.a. Analyze APK
                    if not currentAPK.analyzeAPK():
                        prettyPrint("Analysis of APK \"%s\" failed. Skipping" % path, "warning")
                        continue
                    
                    # 1.b. Check whether trace is saved from previous runs/iterations
                    if os.path.exists("%s/files/tmp/%s_%s.trace" % (getProjectDir(), currentAPK.APK.package, currentAPK.APKType)):
                        prettyPrint("Found a saved trace for %s. Skipping analysis" % currentAPK.APK.package, "info2")
                        continue

                    # 2. Generate Monkeyrunner script
                    if not currentAPK.generateRunnerScript(int(arguments.analysistime)):
                        prettyPrint("Generation of \"Monkeyrunner\" script failed. Skipping", "warning")
                        continue

                    # Define frequently-used commands
                    vboxRestoreCmd = ["vboxmanage", "snapshot", arguments.vmname, "restore", arguments.vmsnapshot]
                    vboxPowerOffCmd = ["vboxmanage", "controlvm", arguments.vmname, "poweroff"]
                    genymotionStartCmd = ["/opt/genymobile/genymotion/player", "--vm-name", arguments.vmname]
                    monkeyRunnerCmd = [monkeyRunnerPath, currentAPK.runnerScript]
                    adbPullCmd = [adbPath, "pull", "/data/data/%s/databases/introspy.db" % str(currentAPK.APK.package)]

                    # 3. Prepare the Genymotion virtual Android device
                    # 3.a. Restore vm to given snapshot
                    if verboseON():
                        prettyPrint("Restoring snapshot \"%s\"" % arguments.vmsnapshot, "debug")
                    result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                    attempts = 1
                    while result.lower().find("error") != -1:
                        print result
                        # Retry restoring snapshot for 10 times and then exit
                        if attempts == 10:
                            prettyPrint("Failed to restore snapshot \"%s\" after 10 attempts. Exiting" % arguments.vmsnapshot, "error")
                            return False
                        prettyPrint("Error encountered while restoring the snapshot \"%s\". Retrying ... %s" % (arguments.vmsnapshot, attempts), "warning")
                        # Make sure the virtual machine is switched off for, both, genymotion and virtualbox
                        if genyProcess:
                            genyProcess.kill()
                        subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        # Now attempt restoring the snapshot
                        result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                        attempts += 1
                        time.sleep(1)

                    # 3.b. Start the Genymotion Android virtual device
                    if verboseON():
                        prettyPrint("Starting the Genymotion machine \"%s\"" % arguments.vmname, "debug")

                    genyProcess = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    if verboseON():
                        prettyPrint("Waiting for machine to boot ...", "debug")
                    time.sleep(20)

                    # 4. Run the generated script
                    prettyPrint("Launching the fuzzing script \"%s\"" % currentAPK.runnerScript)
                    result = subprocess.Popen(monkeyRunnerCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                    while result.lower().find("socket") != -1:
                        prettyPrint("An error occured while running the monkey script. Re-running", "warning")
                        result = subprocess.Popen(monkeyRunnerCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                        
                    # 5. Download the introspy.db
                    #x = raw_input("continue? ")
                    subprocess.Popen(adbPullCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                    # 6. Analyze the downloaded database
                    # 6.a. Check that the database exists and is not empty
                    if os.path.exists("introspy.db"):
                        if int(os.path.getsize("introspy.db")) == 0:
                            prettyPrint("The database generated by Introspy is empty. Skipping", "warning")
                            subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                            genyProcess.kill()
                            continue
                    # Last line of defense
                    try:
                        db = introspy.DBAnalyzer("introspy.db", "foobar")
                    except sqlite3.OperationalError as sql:
                        prettyPrint("The database generated by Introspy is probably empty. Skipping", "warning")
                        continue
                    except sqlite3.DatabaseError as sql:
                        prettyPrint("Database image is malformed. Skipping", "warning")
                        continue

                    jsonTrace = db.get_traced_calls_as_JSON()

                    # 7. Write trace to malware/goodware dir
                    # 7.a. Get a handle
                    apkFileName = path[path.rfind("/")+1:].replace(".apk","")
                    if currentAPK.APKType == "malware": 
                         if path.find("training") != -1:
                             jsonTraceFile = open("%s/%s.json" % (arguments.malwaredir, apkFileName), "w")
                         else:
                             jsonTraceFile = open("%s/%s.json" % (arguments.malwaredirtest, apkFileName), "w")
                    else:
                        if path.find("training") != -1:
                            jsonTraceFile = open("%s/%s.json" % (arguments.goodwaredir, apkFileName), "w")
                        else:
                            jsonTraceFile = open("%s/%s.json" % (arguments.goodwaredirtest, apkFileName), "w")
                    # 7.b. Write content
                    jsonTraceFile.write(jsonTrace)
                    jsonTraceFile.close()

                    # 7.c. Introspy's HTML report
                    #html = introspy.HTMLReportGenerator(db, "foobar") # Second arguments needs to be anythin but ""/None
                    #targetDir = "%s/%s" % (arguments.malwaredir, apkFileName) if currentAPK.APKType == "malware" else "%s/%s" % (arguments.goodwaredir, apkFileName)
                    #if os.path.exists(targetDir):
                    #    shutil.rmtree(targetDir)
                    # Save new report
                    #html.write_report_to_directory(targetDir)
                
                    # 7.d. Extract and save numerical features for SVM's and Trees
                    staticFeatures, dynamicFeatures = extractAndroguardFeatures(path), extractIntrospyFeatures(jsonTraceFile.name)
                    if len(staticFeatures) < 1 or len(dynamicFeatures) < 1:
                        prettyPrint("An error occurred while extracting static or dynamic features. Skipping", "warning")
                        continue
                    # Otherwise, store the features
                    features = dynamicFeatures #staticFeatures + dynamicFeatures TODO: Let's see what dynamic features do on their own
                    if currentAPK.APKType == "malware":
                        if path.find("training") != -1:
                            featuresFile = open("%s/%s.%s" % (arguments.malwaredir, apkFileName, arguments.fileextension), "w")
                        else:
                            featuresFile = open("%s/%s.%s" % (arguments.malwaredirtest, apkFileName, arguments.fileextension), "w")
                    else:
                        if path.find("training") != -1:
                            featuresFile = open("%s/%s.%s" % (arguments.goodwaredir, apkFileName, arguments.fileextension), "w")
                        else:
                           featuresFile = open("%s/%s.%s" % (arguments.goodwaredirtest, apkFileName, arguments.fileextension), "w")


                    featuresFile.write("%s\n" % str(features)[1:-1])
                    featuresFile.close()

                    prettyPrint("Done analyzing \"%s\"" % currentAPK.APK.package)
                    
                    # Delete old introspy.db file
                    os.remove("introspy.db")
 
                    # Shutdown the genymotion machine
                    subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    genyProcess.kill()

            ####################################################################
            # Load the JSON  and feature files as traces before classification #
            ####################################################################
            # Load numerical features
            allFeatureFiles = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.fileextension)) + glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.fileextension))
            allFeatureFilesTest = glob.glob("%s/*.%s" % (arguments.malwaredirtest, arguments.fileextension)) + glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.fileextension))
            allTraceFiles = glob.glob("%s/*.json" % arguments.malwaredir) + glob.glob("%s/*.json" % arguments.goodwaredir)
            allTraceFilesTest = glob.glob("%s/*.json" % arguments.malwaredirtest) + glob.glob("%s/*.json" % arguments.goodwaredirtest)
                
            #######################
            # Hidden Markov Model #
            #######################
            #if arguments.algorithm == "hmm":
            #    prettyPrint("Classifying using HMM and training with \"%s\" instances" % arguments.hmmtrainwith)

                # Build X and y from "allTraces"
            #    X = [t[0] for t in allTraces]
            #    y = [t[1] for t in allTraces]

                # Perform cross validation predicted
            #    predicted = HMM.cross_val_predict(X, y, arguments.hmmtracelength, arguments.hmmthreshold, int(arguments.kfold), arguments.hmmtrainwith)
                # Calculate the performance metrics
            #    metrics = ScikitLearners.calculateMetrics(y, predicted)
            
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
                
            if len(metrics) < 5 or len(metrics_test) < 5:
                prettyPrint("FATAL ERROR: Either or both metrics dicts are incomplete", "error")
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
            

            # Save incorrectly-classified training instances for re-analysis
            reanalyzeMalware, reanalyzeGoodware = [], [] # Reset the lists to store new misclassified instances
            for index in range(len(y)):
                if predicted[index] != y[index]:
                    if arguments.algorithm == "hmm":
                        if allJSONFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allJSONFiles[index])
                        else:
                            reanalyzeGoodware.append(allJSONFiles[index])
                        # Also delete the file
                        # os.unlink(allJSONFiles[index])
  
                    else:
                        # malware instances are in hashes whereas this appends their package names to the list. Update either!!
                        if allFeatureFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk"))
                        else:
                            reanalyzeGoodware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk"))
                        # Also delete the files (.json and .[fileextension])
                        #os.unlink(allFeatureFiles[index])
                        #os.unlink(allFeatureFiles[index].replace(".num", ".json")) 

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
