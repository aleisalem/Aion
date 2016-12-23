#!/usr/bin/python

import ghmm
import time
import sys
from datetime import datetime
#from utils import *


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
        else:
            print "[*] Unable to initialize model. Unequal number of states. %s" % getTimestamp()
            return

    def trainModel(self, trainingData):
        # Expecting training data in the form of a list of malwareSignatures
        if len( trainingData ) < 1:
            print "[*] Empty training set provided. %s" % getTimestamp()
            return False
        # Now use the Baum-Welch algorithm
        self.ghmmModel.baumWelch(ghmm.SequenceSet(self.ghmmModel.emissionDomain, trainingData))
        #print self.ghmmModel
        return True

    def forwardProcedure(self, sequence):
        # Implements the forward procedure algorithm to induce the probability
        # ... of a sequence being produced by the model
        if len(sequence) < 1:
            return 0.0
        N = self.states
        T = range(len(sequence))
        alphas = []
        t = 0
        for state in N:
            alphas.append([]) # Create N-rows/lists as alphas for every state
        # Step 1  - Initialize the alphas alpha1(i) = Pi(i)*bi(o1)
        for state in N:
            alphas[state].append(self.initPi[state] * self.initB[state][sequence[t]])
        # Step 2 - Induction 
        for t in T[1:]: # Iterate over observation sequences 0 <= t < T
            for j in N: # Iterate over states 0 <= j < N
                transitionSum = 0
                for i in N:
                    transitionSum += alphas[i][t-1] * self.initA[i][j]
                alphas[j].append(transitionSum * self.initB[j][sequence[t]])
        # Step 3 -  Termination
        probability = 0
        for i in N:
            probability += alphas[i][T[-1]]
        return probability

