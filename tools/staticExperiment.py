#!/usr/bin/python

from Aion.data_generation.reconstruction.Numerical import *
from Aion.data_inference.learning.ScikitLearners import *
import glob, sys

if len(sys.argv) < 5:
    print "[Usage]: python staticExperiment.py [malware_dir] [goodware_dir] [dataset_name] [feature_type]"
    exit(0)

malware_dir = sys.argv[1]
goodware_dir = sys.argv[2]
dataset_name = sys.argv[3]
feature_type = sys.argv[4]

alldata = glob.glob("%s/*.%s" % (malware_dir, feature_type)) + glob.glob("%s/*.%s" % (goodware_dir, feature_type))

print "[*] Successfully retrieved %s samples" % len(alldata)

X, y = [], []
results = open("static_%s_%s.txt" % (dataset_name, feature_type), "w")

# Load numerical features and populate matrices
for i in alldata:
    print "[*] Processing %s" % i
    vector = loadNumericalFeatures(i)
    if len(vector) < 1:
        print "[*] Empty feature vector returned. Skipping."
        continue
    X.append(vector)
    if i.find("malware") != -1:
        y.append(1)
    else:
        y.append(0)

# Define algorithm variables
K = [10, 25, 50, 100, 250, 500]
E = [10, 25, 50, 75, 100]
tmpPredicted = [0] * len(y)

# Do the KNN's first
for k in K:
    print "[*] Training and testing with KNN's (K=%s)" % k
    predicted = predictKFoldKNN(X, y, K=k, kfold=10, selectKBest=0)
    for i in range(len(predicted)):
        tmpPredicted[i] += predicted[i]
    metrics = calculateMetrics(y, predicted)
    print "###########################"
    print "# Training and Validation #"
    print "###########################"
    print metrics
    results.write("KNN (K=%s)\n" % k)
    results.write("Training and validation\n")
    results.write("%s\n" % metrics)

# Then do the trees
for e in E:
    print "[*] Training and testing with %s-Tree random forest" % e
    predicted = predictKFoldTrees(X, y, kfold=10, selectKBest=0)
    for i in range(len(predicted)):
        tmpPredicted[i] += predicted[i]
    metrics = calculateMetrics(y, predicted)
    print "###########################"
    print "# Training and Validation #"
    print "###########################"
    print metrics
    results.write("%s-Tree Random Forest\n" % e)
    results.write("Training and validation\n")
    results.write("%s\n" % metrics)

# Now Support Vector machines
print "[*] Training testing using a default support vector machine"
predicted = predictKFoldSVM(X, y, kfold=10, selectKBest=0)
for i in range(len(predicted)):
    tmpPredicted[i] += predicted[i]
metrics = calculateMetrics(y, predicted)
print "###########################"
print "# Training and Validation #"
print "###########################"
print metrics
results.write("SVM\n")
results.write("Training and validation\n")
results.write("%s\n" % metrics)

# Calculate majority votes
print "[*] The results according to the ensemble."
classifiers = float(len(K) + len(E) + 1)
predicted = [-1]*len(y)
for i in range(len(tmpPredicted)):
    predicted[i] = 1 if tmpPredicted[i] >= classifiers/2.0 else 0 # 12 classifiers

metrics = calculateMetrics(y, predicted)
print "###########################"
print "# Training and Validation #"
print "###########################"
print metrics

results.write("Ensemble\n")
results.write("Training and validation\n")
results.write("%s\n" % metrics)

results.close()

