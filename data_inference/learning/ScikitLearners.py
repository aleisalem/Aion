#!/usr/bin/python

from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *
from Aion.data_inference.extraction.StringKernelSVM import *

import sklearn, numpy
from sklearn import svm, tree
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import *

import os

def predictKFoldSVMStringKernel(X, y, C=1, kfold=10, subseqLength=3):
    """Classifies the data using Support vector machines with the SSK kernel and k-fold CV
    :param X: The list of text documents containing traces
    :type X: list
    :param y: The labels of documents in 'X'
    :type y: list
    :param C: The 'C' paramter for SVM
    :type C: int (default: 1)
    :param kfold: The number of folds
    :type kfold: int (default: 10)
    :param subseqLength: Length of subsequence
    :type subseqLength: int (default: 3)
    :return: 
    """
    try:
        predicted = []
        # Retrieve Gram Matrix from string kernel
        if verboseON():
            prettyPrint("Generating Gram Matrix from documents", "debug")
        X_gram = string_kernel(X, X)
        y = numpy.array(y)
        # Define classifier
        clf = svm.SVC(kernel="precomputed")
        predicted = cross_val_predict(clf, X_gram, y, cv=kfold).tolist()
    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def predictKFoldSVM(X, y, kernel="linear", C=1, kfold=10):
    """Classifies the data using Support vector machines and k-fold CV"""
    try:
        # Prepare data 
        X, y = numpy.array(X), numpy.array(y)
        # Define classifier
        clf = svm.SVC(kernel=kernel, C=C)
        predicted = cross_val_predict(clf, X, y, cv=kfold).tolist()
    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def predictKFoldTree(X, y, criterion="gini", splitter="best", maxdepth=None, kfold=10):
    """Classifies the data using decision trees and k-fold CV"""
    try:
        # Prepare data
        X, y = numpy.array(X), numpy.array(y)
        # Define classifier
        clf = tree.DecisionTreeClassifier(criterion=criterion, splitter=splitter, max_depth=maxdepth)
        predicted = cross_val_predict(clf, X, y, cv=kfold).tolist()
    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def calculateMetrics(truth, predicted):
    """Calculates and returns a set of metrics from ground truth and predicted vectors"""
    try:
        # Sanity check
        if not len(truth) == len(predicted):
            prettyPrint("The two vectors have different dimensionality", "warning")
            return {}

        metrics = {}
        # Calculate different mterics
        metrics["accuracy"] = accuracy_score(truth, predicted)
        metrics["recall"] = recall_score(truth, predicted)
        metrics["specificity"] = specificity_score(truth, predicted) # From Aion.utils.misc
        metrics["precision"] = precision_score(truth, predicted)
        metrics["f1score"] = f1_score(truth, predicted)

    except Exception as e:
        prettyPrintError(e)
        return {}

    return metrics
