#!/usr/bin/python

from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *
from Aion.data_inference.extraction.StringKernelSVM import *

import sklearn, numpy
from sklearn import svm, tree, neighbors, ensemble
from sklearn.model_selection import cross_val_predict, KFold
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.metrics import *

import os

def calculateMetrics(truth, predicted):
    """
    Calculates and returns a set of metrics from ground truth and predicted vectors
    :param truth: A list of ground truth labels
    :type truth: list
    :param predicted: A list of predicted labels
    :type predicted: list
    :return: A dict of metrics including accuracy, recall, specificity, precision, and F1-score
    """
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

def predictKFoldKNN(X, y, K=10, kfold=10, selectKBest=0):
    """
    Classifies the data using K-nearest neighbors and k-fold CV
    :param X: The list of feature vectors
    :type X: list
    :param y: The list of labels corresponding to the feature vectors
    :type y: list
    :param K: The number of nearest neighbors to consider in classification
    :type K: int
    :param kfold: The number of folds in the CV
    :type kfold: int
    :param selectKBest: The number of best features to select
    :type selectKBest: int
    :return: An array of predicted classes
    """
    try:
        # Prepare data 
        X, y = numpy.array(X), numpy.array(y)
        # Define classifier
        clf = neighbors.KNeighborsClassifier(n_neighbors=K)
        # Select K Best features if enabled
        if selectKBest > 0:
            X_new = SelectKBest(chi2, k=selectKBest).fit_transform(X, y)
            predicted = cross_val_predict(clf, X_new, y, cv=kfold).tolist()
        else:
            predicted = cross_val_predict(clf, X, y, cv=kfold).tolist() 

    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def predictAndTestKFoldKNN(X, y, Xtest, ytest, K=10, kfold=10, selectKBest=0):
    """
    Trains a K-NN using the training data and tests it using the test data using K-fold cross validation
    :type X: list
    :param y: The labels corresponding to the training feature vectors
    :type y: list
    :param Xtest: The matrix of test feature vectors
    :type Xtest: list
    :param ytest: The labels corresponding to the test feature vectors
    :type ytest: list
    :param K: The number of nearest neighbors to consider in classification
    :type K: int
    :param selectKBest: The number of best features to select
    :type selectKBest: int
    :return: Two lists of the validation and test accuracies across the k-folds
    """
    try:
        predicted, predicted_test = [-1] * len(y), []
        # Define classifier and cross validation iterator
        clf = neighbors.KNeighborsClassifier(n_neighbors=K)
        kf = KFold(n_splits=kfold)
        # Start the cross validation learning
        Xtest, ytest = numpy.array(Xtest), numpy.array(ytest)
        foldCounter = 0
        for training_indices, validation_indices in kf.split(X):
            foldCounter += 1
            # Populate training and validation matrices
            Xtrain, ytrain, Xval, yval = [], [], [], []
            index_mapper, index_counter = {}, 0
            for ti in training_indices:
                Xtrain.append(X[ti])
                ytrain.append(y[ti])
            for vi in validation_indices:
                Xval.append(X[vi])
                yval.append(y[vi])
                index_mapper[index_counter] = vi
                index_counter += 1
            # Prepare data
            Xtrain, ytrain, Xval, yval = numpy.array(Xtrain), numpy.array(ytrain), numpy.array(Xval), numpy.array(yval)
            # Select K Best features if enabled
            if selectKBest > 0:
                prettyPrint("Selecting %s best features from feature vectors" % selectKBest)
                Xtrain_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtrain, ytrain)
                Xval_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xval, yval)
                Xtest_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtest, ytest)
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain_new, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval_new)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                temp = clf.predict(Xtest_new)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
            else:
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                prettyPrint("Testing model")
                temp = clf.predict(Xtest)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
        # Now average the predicted lists
        for i in range(len(predicted_test)):
            predicted_test[i] = 1 if predicted_test[i] >= int(kfold/2) else 0

    except Exception as e:
        prettyPrintError(e)
        return [], []

    return predicted, predicted_test


def predictKFoldSVMSSK(X, y, kfold=10, subseqLength=3, selectKBest=0):
    """Classifies the data using Support vector machines with the SSK kernel and k-fold CV
    :param X: The list of text documents containing traces
    :type X: list
    :param y: The labels of documents in 'X'
    :type y: list
    :param kfold: The number of folds
    :type kfold: int (default: 10)
    :param subseqLength: Length of subsequence used by the SSK
    :type subseqLength: int (default: 3)
    :param selectKBest: The number of best features to select
    :type selectKBest: int
    :return: An array of predicted classes 
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
        if selectKBest > 0:
            X_gram_new = SelectKBest(chi2, k=selectKBest).fit_transform(X_gram, y)
            prettyPrint("Performing %s-fold CV on the %s best features" % (kfold, selectKBest))
            predicted = cross_val_predict(clf, X_gram_new, y, cv=kfold).tolist()
        else:
            prettyPrint("Performing %s-fold CV" % kfold)
            predicted = cross_val_predict(clf, X_gram, y, cv=kfold).tolist()
    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def predictAndTestKFoldSVMSSK(X, y, Xtest, ytest, kfold=10, subseqLength=3, selectKBest=0):
    """
    Trains a SVM with the String Subsequence Kernel (SSK) and tests it using the test data and K-fold cross validation
    :param X: The matrix of training feature vectors
    :type X: list
    :param y: The labels corresponding to the training feature vectors
    :type y: list
    :param Xtest: The matrix of test feature vectors
    :type ytest: The labels corresponding to the test feature vectors
    :param kfold: The number of CV folds
    :type kfold: int (default: 10)
    :param subseqLength: Length of subsequence used by the SSK
    :type subseqLength: int (default: 3)
    :param selectKBest: The number of best features to select
    :type selectKBest: int
    :return: Two lists depicting the predicted classes for validation and test vectors
    """
    try:
        # Retrieve Gram matrix from string kernel
        Xtest_gram = string_kernel(Xtest, Xtest) #TODO: Will there be a different Gram matrix for X?
        ytest = numpy.array(y)
        # Define classifier
        clf = svm.SVC(kernel="precomputed")
        # Start the cross-validation learning
        foldCounter = 0
        for training_indices, validation_indices in kf.split(X):
            foldCounter += 1
            # Populate training and validation matrices
            Xtrain, ytrain, Xval, yval = [], [], [], []
            index_mapper, index_counter = {}, 0
            for ti in training_indices:
                Xtrain.append(X[ti])
                ytrain.append(y[ti])
            for vi in validation_indices:
                Xval.append(X[vi])
                yval.append(y[vi])
                index_mapper[index_counter] = vi
                index_counter += 1
            # Prepare data
            Xtrain_gram = string_kernel(Xtrain, Xtrain)
            Xval_gram = string_kernel(Xval, Xval)
            # Select K Best features if enabled
            if selectKBest > 0:
                prettyPrint("Selecting %s best features" % selectKBest)
                Xtrain_gram_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtrain_gram, ytrain)
                Xval_gram_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xval_gram, y_val)
                Xtest_gram_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtest_gram, y_test)
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain_gram_new, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval_gram_new)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                temp = clf.predict(Xtest_gram_new)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
            else:
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain_gram, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval_gram)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                temp = clf.predict(Xtest_gram)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
        # Now average the predicted lists
        prettyPrint("Testing model")
        for i in range(len(predicted_test)):
            predicted_test[i] = 1 if predicted_test[i] >= int(kfold/2) else 0

    except Exception as e:
        prettyPrintError(e)
        return [], []
 
    return predicted, predicted_test

def predictKFoldSVM(X, y, kernel="linear", C=1, selectKBest=0, kfold=10):
    """
    Classifies the data using Support vector machines and k-fold CV
    :param X: The matrix of feature vectors
    :type X: list
    :param y: The vector containing the labels corresponding to feature vectors
    :type y: list
    :param kernel: The kernel used to elevate data into higher dimensionalities
    :type kernel: str
    :param C: The penalty parameter of the error term
    :type C: int
    :param selectKBest: The number of best features to select
    :type selectKBest: int 
    :param kfold: The number of folds to use in K-fold CV
    :type kfold: int
    :return: A list of predicted labels across the k-folds
    """
    try:
        # Prepare data 
        X, y = numpy.array(X), numpy.array(y)
        # Define classifier
        clf = svm.SVC(kernel=kernel, C=C)
        # Select K Best features if enabled
        if selectKBest > 0:
            X_new = SelectKBest(chi2, k=selectKBest).fit_transform(X, y)
            predicted = cross_val_predict(clf, X_new, y, cv=kfold).tolist()
        else:
            predicted = cross_val_predict(clf, X, y, cv=kfold).tolist()
    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def predictAndTestKFoldSVM(X, y, Xtest, ytest, kernel="linear", C=1, selectKBest=0, kfold=10):
    """
    Trains a SVM using the training data and tests it using the test data using K-fold cross validation
    :param X: The matrix of training feature vectors
    :type X: list
    :param y: The labels corresponding to the training feature vectors
    :type y: list
    :param Xtest: The matrix of test feature vectors
    :type Xtest: list
    :param ytest: The labels corresponding to the test feature vectors
    :type ytest: list
    :param kernel: The kernel used by the traing SVM's
    :type kernel: str
    :param C: The penalty parameter of the error term
    :type C: int
    :param selectKBest: The number of best features to select
    :type selectKBest: int
    :param kfold: The number of folds to use in K-fold CV
    :type kfold: int
    :return: Two lists of the validation and test accuracies across the 10 folds
    """
    try:
        predicted, predicted_test = [-1] * len(y), []
        # Define classifier and cross validation iterator
        clf = svm.SVC(kernel=kernel, C=C)
        kf = KFold(n_splits=kfold)
        # Start the cross validation learning
        Xtest, ytest = numpy.array(Xtest), numpy.array(ytest)
        foldCounter = 0
        for training_indices, validation_indices in kf.split(X):
            foldCounter += 1
            # Populate training and validation matrices
            Xtrain, ytrain, Xval, yval = [], [], [], []
            index_mapper, index_counter = {}, 0
            for ti in training_indices:
                Xtrain.append(X[ti])
                ytrain.append(y[ti])
            for vi in validation_indices:
                Xval.append(X[vi])
                yval.append(y[vi])
                index_mapper[index_counter] = vi
                index_counter += 1                
            # Prepare data
            Xtrain, ytrain, Xval, yval = numpy.array(Xtrain), numpy.array(ytrain), numpy.array(Xval), numpy.array(yval)
            # Select K Best features if enabled
            if selectKBest > 0:
                prettyPrint("Selecting %s best features from feature vectors" % selectKBest)
                Xtrain_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtrain, ytrain)
                Xval_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xval, yval)
                Xtest_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtest, ytest)
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain_new, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval_new)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                temp = clf.predict(Xtest_new)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
            else:
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                prettyPrint("Testing model")
                temp = clf.predict(Xtest)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
        # Now average the predicted lists
        for i in range(len(predicted_test)):
            predicted_test[i] = 1 if predicted_test[i] >= int(kfold/2) else 0

    except Exception as e:
        prettyPrintError(e)
        return [], []

    return predicted, predicted_test
    

def predictKFoldTrees(X, y, estimators=10, criterion="gini", maxdepth=None, selectKBest=0, kfold=10):
    """
    Classifies the data using decision trees and k-fold CV
    :param X: The matrix of feature vectors
    :type X: list
    :param y: The vector containing labels corresponding to the feature vectors
    :type y: list
    :param estimators: The number of random trees to use in classification
    :type estimators: int
    :param criterion: The splitting criterion employed by the decision tree
    :type criterion: str
    :param splitter: The method used to split the data
    :type splitter: str
    :param maxDepth: The maximum depth the tree is allowed to grow
    :type maxDepth: int
    :param selectKBest: The number of best features to select
    :type selectKBest: int
    :param kfold: The number of folds to use in K-fold CV
    :type kfold: int
    :return: A list of predicted labels across the k-folds
    """
    try:
        # Prepare data
        X, y = numpy.array(X), numpy.array(y)
        # Define classifier
        clf = ensemble.RandomForestClassifier(n_estimators=estimators, criterion=criterion, max_depth=maxdepth)
        if selectKBest > 0:
            X_new = SelectKBest(chi2, k=selectKBest).fit_transform(X, y)
            predicted = cross_val_predict(clf, X_new, y, cv=kfold).tolist()
        else:
            predicted = cross_val_predict(clf, X, y, cv=kfold).tolist()
    except Exception as e:
        prettyPrintError(e)
        return []

    return predicted

def predictAndTestKFoldTrees(X, y, Xtest, ytest, estimators=10, criterion="gini", maxdepth=None, selectKBest=0, kfold=10):
    """
    Trains a tree using the training data and tests it using the test data using K-fold cross validation
    :param Xtr: The matrix of training feature vectors
    :type Xtr: list
    :param ytr: The labels corresponding to the training feature vectors
    :type ytr: list
    :param Xte: The matrix of test feature vectors
    :type yte: list
    :param estimators: The number of random trees to use in classification
    :type estimators: int
    :param criterion: The splitting criterion employed by the decision tree
    :type criterion: str
    :param splitter: The method used to split the data 
    :type splitter: str
    :param maxdepth: The maximum depth the tree is allowed to grow
    :type maxdepth: int
    :param selectKBest: The number of best features to select
    :type selectKBest: int 
    :param kfold: The number of folds to use in K-fold CV
    :type kfold: int
    :return: Two lists of the validation and test accuracies across the 10 folds
    """
    try:
        predicted, predicted_test = [-1] * len(y), []
        # Define classifier and cross validation iterator
        clf = ensemble.RandomForestClassifier(n_estimators=estimators, criterion=criterion, max_depth=maxdepth)
        kf = KFold(n_splits=kfold)
        # Start the cross validation learning
        Xtest, ytest = numpy.array(Xtest), numpy.array(ytest)
        foldCounter = 0
        for training_indices, validation_indices in kf.split(X):
            foldCounter += 1
            # Populate training and validation matrices
            Xtrain, ytrain, Xval, yval = [], [], [], []
            index_mapper, index_counter = {}, 0
            for ti in training_indices:
                Xtrain.append(X[ti])
                ytrain.append(y[ti])
            for vi in validation_indices:
                Xval.append(X[vi])
                yval.append(y[vi])
                index_mapper[index_counter] = vi
                index_counter += 1
            Xtrain, ytrain, Xval, yval = numpy.array(Xtrain), numpy.array(ytrain), numpy.array(Xval), numpy.array(yval)
            # Select K Best features if enabled
            if selectKBest > 0:
                prettyPrint("Selecting %s best features from feature vectors" % selectKBest)
                Xtrain_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtrain, ytrain)
                Xval_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xval, yval)
                Xtest_new = SelectKBest(chi2, k=selectKBest).fit_transform(Xtest, ytest)
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain_new, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval_new)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                prettyPrint("Testing model")
                temp = clf.predict(Xtest_new)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
            else:
                # Fit model
                prettyPrint("Fitting model: Fold %s out of %s" % (foldCounter, kfold))
                clf.fit(Xtrain, ytrain)
                # Validate and test model
                prettyPrint("Validating model")
                temp = clf.predict(Xval)
                for i in range(len(temp)):
                    predicted[index_mapper[i]] = temp[i]
                prettyPrint("Testing model")
                temp = clf.predict(Xtest)
                predicted_test = [predicted_test[i]+temp[i] for i in range(len(temp))] if len(predicted_test) == len(temp) else temp
        # Now average the predicted lists
        for i in range(len(predicted_test)):
            predicted_test[i] = 1 if predicted_test[i] >= int(kfold/2) else 0

    except Exception as e:
        prettyPrintError(e)
        return [], []

    return predicted, predicted_test



