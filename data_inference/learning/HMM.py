#!/usr/bin/python

from Aion.utils.graphics import *
from Aion.utils.data import *
from Aion.utils.misc import *

import ghmm
from datetime import datetime
from sklearn.cross_validation import KFold
from sklearn.metrics import *
import numpy

import time, sys

class HiddenMarkovModel():
    # A simple structure to represent a hidden Markov model
    def __init__(self, A, B, Pi, observations):
        if len(A) == len(Pi):
            self.states = range(len(A))
            self.sigma = ghmm.Alphabet(observations) # The "alphabet" comprising action indices
            self.initA = A
            self.initB = B
            self.initPi = Pi
            self.ghmmModel = ghmm.HMMFromMatrices(self.sigma, ghmm.DiscreteDistribution(self.sigma), self.initA, self.initB, self.initPi)
            self.isTrained = False
        else:
            prettyPrint("Unable to initialize model. Unequal number of states", "error")
            return

    def train(self, X):
        """Uses GHMM's implementation of Baum-Welch to train an HMM"""
        try:
            if len(X) < 1:
                prettyPrint("Empty training set provided", "warning")
                return False
            # Now use the Baum-Welch algorithm
            self.ghmmModel.baumWelch(ghmm.SequenceSet(self.ghmmModel.emissionDomain, X))
            self.isTrained = True
            if verboseON():
                print "Trained model: %s" % self.ghmmModel

        except Exception as e:
            prettyPrintError(e)
            return False

        return True

def cross_val_predict(X, y, tracelength, threshold, kfold=10, trainwith="malware"):
    """Classifies out-of-sample sequences using the trained model and KFold CV"""
    try:
        # Retrieve indices
        outIndices = [] # The ranges of the instances not to be used in training (Assumed trailing)
        for index in range(len(X)):
            if trainwith == "malware" and y[index] == 0:
                outIndices.append(index)
            elif trainwith =="goodware" and y[index] == 1:
               outIndices.append(index)

        # A matrix to hold the predictions (len(X) x Kfold)
        P = numpy.zeros((len(X), kfold))

        Xmal, Xgood, ymal, ygood = [], [], [], []
        for index in range(len(X)):
            if y[index] == 1:
                Xmal.append(X[index])
                ymal.append(y[index])
            elif y[index] == 0:
                Xgood.append(X[index])
                ygood.append(y[index]) 
 
        allFolds = KFold(len(Xmal), kfold) if trainwith == "malware" else KFold(len(Xgood), kfold)
        currentFold = 1
        for trainingIndices, testIndices in allFolds:
            Xtrain, Xtest = [], []
            ytrain, ytest = [], []
            # Populate training traces
            for index in trainingIndices:
                if trainwith == "malware":
                    Xtrain.append(Xmal[index])
                    ytrain.append(ymal[index])
                else:
                    Xtrain.append(Xgood[index])
                    ytrain.append(ygood[index])
            # Populate test traces
            for index in testIndices:
                if trainwith == "malware":
                    Xtest.append(Xmal[index])
                    ytest.append(ymal[index])
                else:
                    Xtest.append(Xgood[index])
                    ytest.append(ygood[index])
        
            #print ytrain, ytest
            if trainwith == "malware":
                Xtest = Xtest + Xgood
                ytest = ytest + ygood
            else:
                Xtest = Xtest + Xmal
                ytest = ytest + ymal
        
            #print ytrain, ytest
            Pindices = testIndices.tolist() + outIndices # TODO: Use this to populate "P"
            #print Pindices
            
            # Get the observations from the current training and test datasets
            predicted = []
            allObservations = []
            for trace in Xtrain + Xtest:
                for call in trace:
                    if not call in allObservations:
                        allObservations.append(call)
            if verboseON():
                prettyPrint("Successfully retrieved %s observations from current traces" % len(allObservations), "debug")
            # Prepare HMM
            Pi = [1.0, 0.0]
            A = [[0.5, 0.5], [0.5, 0.5]]
            B = numpy.random.random((2, len(allObservations))).tolist()

            prettyPrint("Building the hidden Markov model")
            hmm = HiddenMarkovModel(A, B, Pi, allObservations)

            prettyPrint("Training the model")
            hmm.train(Xtrain)

            # Test model
            for index in range(len(Xtest)):
                # Retrieve and prepare trace
                currentTrace, currentClass = Xtest[index], ytest[index]
                currentTrace = currentTrace[:int(tracelength)] if len(currentTrace) > int(tracelength) else currentTrace
                currentTrace = ghmm.EmissionSequence(hmm.sigma, currentTrace)
                # Calculate log likelihood 
                logProbability = hmm.ghmmModel.loglikelihood(currentTrace)
                if verboseON():
                    prettyPrint("P(O|lambda)=%s" % logProbability, "debug")
                # Classify instance
                if trainwith == "malware":
                    currentPredicted = 0 if logProbability <= -int(threshold) else 1
                else:
                    currentPredicted = 1 if logProbability <= -int(threshold) else 0

                # Append to predicted
                if verboseON():
                    prettyPrint("%s instance classified as %s" % (["Goodware", "Malware"][ytest[index]], ["Goodware", "Malware"][currentPredicted]), "debug")
                predicted.append(currentPredicted)

            # Populate the prediction matrix
            #print P.shape
            #print Pindices, len(Pindices)
            #print predicted, len(predicted)
            #print currentFold
            for index in range(len(predicted)):
                #print "P[%s][%s] = %s" % (Pindices[index], currentFold-1, predicted[index])
                P[Pindices[index]][currentFold-1] = predicted[index]

            currentFold += 1 # Increment the fold number

        # For each instance, calculate the majority vote of predictons
        predicted = []
        #print P
        for rIndex in range(P.shape[0]):
            if rIndex >= outIndices[0]:
                if sum(P[rIndex,:]) >= kfold/2:
                    predicted.append(1)
                else:
                    predicted.append(0)
            else:
                # Malware instances will only be used once as test instances
                if sum(P[rIndex,:] > 0):
                    predicted.append(1)
                else:
                    predicted.append(0)

    except Exception as e:
        prettyPrintError(e)
        return [] 

    return predicted

