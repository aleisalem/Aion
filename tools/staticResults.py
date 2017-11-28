#!/usr/bin/python

from Aion.utils.data import *     # Needed for accessing configuration files
from Aion.utils.graphics import * # Needed for pretty printing
from Aion.utils.misc import *

import os, sys, glob, shutil, argparse



def defineArguments():
    parser = argparse.ArgumentParser(prog="staticResults.py", description="A tool to average the results from X runs of Aion's static experiment I")
    parser.add_argument("-d", "--resultdir", help="The directory containing results text files", required=True)
    parser.add_argument("-t", "--featuretype", help="The type of the features used in classification", required=True)
    parser.add_argument("-n", "--datasetname", help="The name of the dataset to which the results belong", required=True)
    parser.add_argument("-e", "--experiment", help="Whether the experiment is static or dynamic", choices=["static", "dynamic"], default="static", required=False)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the \"Aion\"'s static experiment I printer")

        # 1. Retrieve files
        allFiles = glob.glob("%s/*.txt" % arguments.resultdir)
        if len(allFiles) < 1:
            prettyPrint("Unable to retrieve any results files. Exiting", "error")
            return False
 
        prettyPrint("Successfully retrieved %s result files" % len(allFiles))
        # 2. Parse files
        results = {"training": {}, "test": {}}
        for f in allFiles:
            prettyPrint("Processing \"%s\"" % f)
            lines = open(f).read().split('\n')
            mode, classifier, result = "", "", {}
            for line in lines:
                # 2.a. Get mode i.e. training/test
                mode = "training" if line.lower().find("training") != -1 else mode
                mode = "test" if line.lower().find("test") != -1 else mode
                # 2.b. Get the classifier's name
                classifier = line[line.rfind(' ')+1:-1] if line.lower().find("results") != -1 else classifier
                # 2.c. Lastly, get the results
                result = eval(line) if line.lower().find("f1score") != -1 else result
                if mode != "" and classifier != "" and len(result) > 0:
                    if classifier not in results[mode].keys():
                        # Add results to directionary
                        results[mode][classifier] = {"accuracy": [result["accuracy"]], "recall": [result["recall"]], "specificity": [result["specificity"]], "precision": [result["precision"]], "f1score": [result["f1score"]]}
                    else:
                        # Append results
                        results[mode][classifier]["accuracy"].append(result["accuracy"])
                        results[mode][classifier]["recall"].append(result["recall"])
                        results[mode][classifier]["specificity"].append(result["specificity"])
                        results[mode][classifier]["precision"].append(result["precision"])
                        results[mode][classifier]["f1score"].append(result["f1score"])
                    mode, classifier, result = "", "", {}

        # 3. Average the results
        training, test = results["training"], results["test"]
        resultsFile = open("avg_results_%s_%s_%s.txt" % (arguments.datasetname, arguments.featuretype, arguments.experiment), "w")
        learners = training.keys()
        learners.sort()
        for learner in learners:
            accuracy = float(sum(training[learner]["accuracy"])/float(len(allFiles)))
            recall = float(sum(training[learner]["recall"])/float(len(allFiles)))
            specificity = float(sum(training[learner]["specificity"])/float(len(allFiles)))
            precision = float(sum(training[learner]["precision"])/float(len(allFiles)))
            f1score = float(sum(training[learner]["f1score"])/float(len(allFiles)))
            resultsFile.write("[Training: %s]\n" % learner)
            resultsFile.write("Accuracy: %s, Recall: %s, Specificity: %s, Precision: %s, F1Score: %s\n\n" % (accuracy, recall, specificity, precision, f1score))

        learners = test.keys()
        learners.sort()
        for learner in learners:
            accuracy = float(sum(test[learner]["accuracy"])/float(len(allFiles)))
            recall = float(sum(test[learner]["recall"])/float(len(allFiles)))
            specificity = float(sum(test[learner]["specificity"])/float(len(allFiles)))
            precision = float(sum(test[learner]["precision"])/float(len(allFiles)))
            f1score = float(sum(test[learner]["f1score"])/float(len(allFiles)))
            resultsFile.write("[Test: %s]\n" % learner)
            resultsFile.write("Accuracy: %s, Recall: %s, Specificity: %s, Precision: %s, F1Score: %s\n\n" % (accuracy, recall, specificity, precision, f1score))

        resultsFile.close()

    except Exception as e:
        prettyPrintError(e)
        return False

    return True

if __name__ == "__main__":
    main()
