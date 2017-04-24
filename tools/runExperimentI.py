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
from droidutan import Droidutan

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
    parser.add_argument("-q", "--waitboot", help="The number of seconds to wait for the Genymotion machine to boot before running the stimulation script", required=False, default=20)
    parser.add_argument("-a", "--algorithm", help="The machine learning algorithm to use for classification", required=True, choices=["hmm", "associative", "svm"])
    parser.add_argument("-k", "--kfold", help="Whether to use k-fold cross validation and the value of \"K\"", required=False, default=2)
    parser.add_argument("-p", "--fileextension", help="The extension of feature files", required=False, default="txt")
    parser.add_argument("-u", "--svmusessk", help="Whether to use the SSK kernel with SVM", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-n", "--svmsubsequence", help="The length of the subsequence to consider upon using SVM's with the SSK", required=False, default=3)
    parser.add_argument("-w", "--hmmtrainwith", help="Whether to train the HMM with malicious or benign instances", required=False, default="malware", choices=["malware", "goodware"])
    parser.add_argument("-l", "--hmmtracelength", help="The maximum trace length to consider during testing", required=False, default=50)
    parser.add_argument("-e", "--hmmthreshold", help="The likelihood threshold to apply during testing", required=False, default=-500)
    parser.add_argument("-o", "--outfile", help="The path to the file to log classification results", required=False, default="")
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

                for path in allAPKs:
                    if not reanalysis:
                        # 0. Ignore previously-analyzed APK's that are not in for re-analysis
                        if os.path.exists(path.replace(".apk", "_%s.%s" % (arguments.vmname, arguments.fileextension))):
                            # Second line of defense
                            if not path in reanalyzeMalware + reanalyzeGoodware:
                                prettyPrint("APK \"%s\" has been analyzed before. Skipping" % path, "warning")
                                continue

                    # 1. Statically analyze the APK using androguard
                    APKType = "malware" if path in malAPKs else "goodware"
                    apk, dx, vm = Droidutan.analyzeAPK(path)
                    appComponents = Droidutan.extractAppComponents(apk)
 
                    if verboseON():
                        prettyPrint("Analyzing APK: \"%s\"" % path, "debug")

                    # 2. Get the Ip address assigned to the AVD
                    getAVDIPCmd = ["VBoxManage", "guestproperty", "enumerate", arguments.vmname]
                    avdIP = ""
                    result = subprocess.Popen(getAVDIPCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0].replace(' ', '')
                    if result.lower().find("error") != -1:
                         prettyPrint("Unable to retrieve the IP address of the AVD", "error")
                         print result
                         continue
                    index = result.find("androvm_ip_management,value:")+len("androvm_ip_management,value:")
                    while result[index] != ',':
                        avdIP += result[index]
                        index += 1
                    adbID = "%s:5555" % avdIP

                    # 3. Define frequently-used commands
                    adbPath = "%s/platform-tools/adb" % arguments.sdkdir
                    vboxRestoreCmd = ["vboxmanage", "snapshot", arguments.vmname, "restore", arguments.vmsnapshot]
                    vboxPowerOffCmd = ["vboxmanage", "controlvm", arguments.vmname, "poweroff"]
                    genymotionStartCmd = ["/opt/genymobile/genymotion/player", "--vm-name", arguments.vmname]
                    genymotionPowerOffCmd = ["/opt/genymobile/genymotion/player", "--poweroff", "--vm-name", arguments.vmname]
                    introspyDBName = "introspy_%s.db" % arguments.vmname
                    adbPullCmd = [adbPath, "-s", adbID, "pull", "/data/data/%s/databases/introspy.db" % appComponents["package_name"], introspyDBName]
                    appUninstallCmd = [adbPath, "-s", adbID, "uninstall", appComponents["package_name"]]

                    # 4. Prepare the Genymotion virtual Android device
                    # 4.a. Restore vm to given snapshot
                    #if verboseON():
                    #    prettyPrint("Restoring snapshot \"%s\"" % arguments.vmsnapshot, "debug")
                    #result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                    #attempts = 1
                    #while result.lower().find("error") != -1:
                    #    print result
                    #    # Retry restoring snapshot for 10 times and then exit
                    #    if attempts == 10:
                    #        prettyPrint("Failed to restore snapshot \"%s\" after 10 attempts. Exiting" % arguments.vmsnapshot, "error")
                    #        return False
                    #    prettyPrint("Error encountered while restoring the snapshot \"%s\". Retrying ... %s" % (arguments.vmsnapshot, attempts), "warning")
                    #    # Make sure the virtual machine is switched off for, both, genymotion and virtualbox
                    #    subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    #    # Now attempt restoring the snapshot
                    #    result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                    #    attempts += 1
                    #    time.sleep(1)

                    # 4.b. Start the Genymotion Android virtual device
                    #if verboseON():
                    #    prettyPrint("Starting the Genymotion machine \"%s\"" % arguments.vmname, "debug")

                    #genyProcess = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    #if verboseON():
                    #    prettyPrint("Waiting for machine to boot ...", "debug")
                    #time.sleep(int(arguments.waitboot))


                    # 5. Test the APK using Droidutan TODO: Assuming the machine is already on!
                    prettyPrint("Testing the APK using Droidutan")
                    # 5.a. Unleash Droidutan
                    if not Droidutan.testApp(path, avdSerialno=avdIP, testDuration=int(arguments.analysistime), useIntrospy=True, preExtractedComponents=appComponents):
                        prettyPrint("An error occurred while testing the APK \"%s\". Skipping" % path, "warning")
                        #subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        #subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        #genyProcess.kill()
                        prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
                        subprocess.Popen(appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        continue

                    # 5.b. Download the introspy.db
                    subprocess.Popen(adbPullCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

                    # 5.c. Uninstall the app
                    prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
                    subprocess.Popen(appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)

                    # 6. Analyze the downloaded database
                    # 6.a. Check that the database exists and is not empty
                    if os.path.exists(introspyDBName):
                        if int(os.path.getsize(introspyDBName)) == 0:
                            prettyPrint("The database generated by Introspy is empty. Skipping", "warning")
                            #subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                            #subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                            #genyProcess.kill()
                            prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
                            subprocess.Popen(appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                            continue
                    # Last line of defense
                    try:
                        db = introspy.DBAnalyzer(introspyDBName, "foobar")
                    except sqlite3.OperationalError as sql:
                        prettyPrint("The database generated by Introspy is probably empty. Skipping", "warning")
                        #subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        #genyProcess.kill()
                        prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
                        subprocess.Popen(appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        continue
                    except sqlite3.DatabaseError as sql:
                        prettyPrint("Database image is malformed. Skipping", "warning")
                        #subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        #genyProcess.kill()
                        prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
                        subprocess.Popen(appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                        continue

                    jsonTrace = db.get_traced_calls_as_JSON()

                    # 7. Write trace to malware/goodware dir
                    # 7.a. Get a handle
                    apkFileName = path[path.rfind("/")+1:].replace(".apk","")
                    if APKType == "malware": 
                         if path.find("training") != -1:
                             jsonTraceFile = open("%s/%s_%s.json" % (arguments.malwaredir, apkFileName, arguments.vmname), "w")
                         else:
                             jsonTraceFile = open("%s/%s_%s.json" % (arguments.malwaredirtest, apkFileName, arguments.vmname), "w")
                    else:
                        if path.find("training") != -1:
                            jsonTraceFile = open("%s/%s_%s.json" % (arguments.goodwaredir, apkFileName, arguments.vmname), "w")
                        else:
                            jsonTraceFile = open("%s/%s_%s.json" % (arguments.goodwaredirtest, apkFileName, arguments.vmname), "w")
                    # 7.b. Write content
                    jsonTraceFile.write(jsonTrace)
                    jsonTraceFile.close()

                    # 7.c. Extract and save numerical features for SVM's and Trees
                    staticFeatures, dynamicFeatures = extractAndroguardFeatures(path), extractIntrospyFeatures(jsonTraceFile.name)
                    if len(staticFeatures) < 1 or len(dynamicFeatures) < 1:
                        prettyPrint("An error occurred while extracting static or dynamic features. Skipping", "warning")
                        continue
                    # Otherwise, store the features
                    features = staticFeatures + dynamicFeatures # TODO: Can static features help with the mediocre specificity scores?
                    if APKType == "malware":
                        if path.find("training") != -1:
                            featuresFile = open("%s/%s_%s.%s" % (arguments.malwaredir, apkFileName, arguments.vmname, arguments.fileextension), "w")
                        else:
                            featuresFile = open("%s/%s_%s.%s" % (arguments.malwaredirtest, apkFileName, arguments.vmname, arguments.fileextension), "w")
                    else:
                        if path.find("training") != -1:
                            featuresFile = open("%s/%s_%s.%s" % (arguments.goodwaredir, apkFileName, arguments.vmname, arguments.fileextension), "w")
                        else:
                           featuresFile = open("%s/%s_%s.%s" % (arguments.goodwaredirtest, apkFileName, arguments.vmname, arguments.fileextension), "w")


                    featuresFile.write("%s\n" % str(features)[1:-1])
                    featuresFile.close()

                    prettyPrint("Done analyzing \"%s\"" % appComponents["package_name"])
                    
                    # Delete old introspy.db file
                    os.remove(introspyDBName)
 
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
                
            metrics, metrics_test = {}, {}
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
                        if allJSONFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allJSONFiles[index].replace("_%s" % arguments.vmname, ""))
                        else:
                            reanalyzeGoodware.append(allJSONFiles[index].replace("_%s" % arguments.vmname, ""))
                        # Also delete the file
                        # os.unlink(allJSONFiles[index])
  
                    else:
                        # malware instances are in hashes whereas this appends their package names to the list. Update either!!
                        if allFeatureFiles[index].find("malware") != -1:
                            reanalyzeMalware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk").replace("_%s" % arguments.vmname, ""))
                        else:
                            reanalyzeGoodware.append(allFeatureFiles[index].replace(arguments.fileextension, "apk").replace("_%s" % arguments.vmname, ""))
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
