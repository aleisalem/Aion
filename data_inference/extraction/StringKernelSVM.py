#!/usr/bin/python

####################################################
# DISCLAIMER: This code is a slightly-edited copy  #
# of Tim Shenkao's "stringSVM.py" available on the #
# github repo "StringKernelSVM"                    #
# https://github.com/timshenkao/StringKernelSVM    #
####################################################

import numpy as np
import sys
from time import time

def _K(n, s, t, lambda_decay=0.5):
    """
    K_n(s,t) in the original article; recursive function
    :param n: length of subsequence
    :type n: int
    :param s: document #1
    :type s: str
    :param t: document #2
    :type t: str
    :return: float value for similarity between s and t
    """
    if min(len(s), len(t)) < n:
        return 0
    else:
        part_sum = 0
        for j in range(1, len(t)):
            if t[j] == s[-1]:
                #not t[:j-1] as in the article but t[:j] because of Python slicing rules!!!
                part_sum += _K1(n - 1, s[:-1], t[:j])
        result = _K(n, s[:-1], t) + lambda_decay ** 2 * part_sum
        return result

def _K1(n, s, t, lambda_decay=0.5):
    """
    K'_n(s,t) in the original article; auxiliary intermediate function; recursive function
    :param n: length of subsequence
    :type n: int
    :param s: document #1
    :type s: str
    :param t: document #2
    :type t: str
    :return: intermediate float value
    """
    if n == 0:
        return 1
    elif min(len(s), len(t)) < n:
        return 0
    else:
        part_sum = 0
        for j in range(1, len(t)):
            if t[j] == s[-1]:
    #not t[:j-1] as in the article but t[:j] because of Python slicing rules!!!
                part_sum += _K1(n - 1, s[:-1], t[:j]) * (lambda_decay ** (len(t) - (j + 1) + 2))
        result = lambda_decay * _K1(n, s[:-1], t) + part_sum
        return result

def _gram_matrix_element(s, t, sdkvalue1, sdkvalue2, subseq_length=3):
    """
    Helper function
    :param s: document #1
    :type s: str
    :param t: document #2
    :type t: str
    :param sdkvalue1: K(s,s) from the article
    :type sdkvalue1: float
    :param sdkvalue2: K(t,t) from the article
    :type sdkvalue2: float
    :return: value for the (i, j) element from Gram matrix
    """
    if s == t:
        return 1
    else:
        try:
            return _K(subseq_length, s, t) / \
                   (sdkvalue1 * sdkvalue2) ** 0.5
        except ZeroDivisionError:
            print("Maximal subsequence length is less or equal to documents' minimal length. You should decrease it")
            sys.exit(2)

def string_kernel(X1, X2, subseq_length=3, lambda_decay=0.5):
    """
    String Kernel computation
    :param X1: list of documents (m rows, 1 column); each row is a single document (string)
    :type X1: list
    :param X2: list of documents (m rows, 1 column); each row is a single document (string)
    :type X2: list
    :return: Gram matrix for the given parameters
    """
    len_X1 = len(X1)
    len_X2 = len(X2)
    # numpy array of Gram matrix
    gram_matrix = np.zeros((len_X1, len_X2), dtype=np.float32)
    sim_docs_kernel_value = {}
    #when lists of documents are identical
    if X1 == X2:
    #store K(s,s) values in dictionary to avoid recalculations
        for i in range(len_X1):
            sim_docs_kernel_value[i] = _K(subseq_length, X1[i], X1[i])
    #calculate Gram matrix
        for i in range(len_X1):
            for j in range(i, len_X2):
                gram_matrix[i, j] = _gram_matrix_element(X1[i], X2[j], sim_docs_kernel_value[i], sim_docs_kernel_value[j])
    #using symmetry
                gram_matrix[j, i] = gram_matrix[i, j]
    #when lists of documents are not identical but of the same length
    elif len_X1 == len_X2:
        sim_docs_kernel_value[1] = {}
        sim_docs_kernel_value[2] = {}
    #store K(s,s) values in dictionary to avoid recalculations
        for i in range(len_X1):
            sim_docs_kernel_value[1][i] = _K(subseq_length, X1[i], X1[i])
        for i in range(len_X2):
            sim_docs_kernel_value[2][i] = _K(subseq_length, X2[i], X2[i])
    #calculate Gram matrix
        for i in range(len_X1):
            for j in range(i, len_X2):
                gram_matrix[i, j] = _gram_matrix_element(X1[i], X2[j], sim_docs_kernel_value[1][i], sim_docs_kernel_value[2][j])
    #using symmetry
                gram_matrix[j, i] = gram_matrix[i, j]
    #when lists of documents are neither identical nor of the same length
    else:
        sim_docs_kernel_value[1] = {}
        sim_docs_kernel_value[2] = {}
        min_dimens = min(len_X1, len_X2)
    #store K(s,s) values in dictionary to avoid recalculations
        for i in range(len_X1):
            sim_docs_kernel_value[1][i] = _K(subseq_length, X1[i], X1[i])
        for i in range(len_X2):
            sim_docs_kernel_value[2][i] = _K(subseq_length, X2[i], X2[i])
    #calculate Gram matrix for square part of rectangle matrix
        for i in range(min_dimens):
            for j in range(i, min_dimens):
                gram_matrix[i, j] = _gram_matrix_element(X1[i], X2[j], sim_docs_kernel_value[1][i], sim_docs_kernel_value[2][j])
                #using symmetry
                gram_matrix[j, i] = gram_matrix[i, j]

    #if more rows than columns
        if len_X1 > len_X2:
            for i in range(min_dimens, len_X1):
                for j in range(len_X2):
                    gram_matrix[i, j] = _gram_matrix_element(X1[i], X2[j], sim_docs_kernel_value[1][i], sim_docs_kernel_value[2][j])
        #if more columns than rows
        else:
            for i in range(len_X1):
                for j in range(min_dimens, len_X2):
                    gram_matrix[i, j] = _gram_matrix_element(X1[i], X2[j], sim_docs_kernel_value[1][i],
                                                                     sim_docs_kernel_value[2][j])
    print sim_docs_kernel_value
    return gram_matrix
