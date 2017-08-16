#!/usr/bin/python


import glob, sys

from Aion.data_inference.extraction.featureExtraction import *

if len(sys.argv) < 2:
    print "[Usage]: python extractStatic.py [app_dir]"
    exit(0)

app_dir = sys.argv[1]

alldata = glob.glob("%s/*.apk" % app_dir)

if len(alldata) < 1:
    print "[*] Unable to retrieve APK's from the directories \"%s\"" % (app_dir)
    exit(0)

print "[*] Successfully retrieved %s APK's from  the directories \"%s\"" % (len(alldata), app_dir)

# Commence analysis
counter = 1
for a in alldata:
    try:
        print "Analyzing app #%s out of %s apps" % (counter, len(alldata))
        basic, permissions, apicalls, allfeatures = extractStaticFeatures(a)
        print basic, permissions, apicalls, allfeatures
        print "[*] Saving basic features to \"%s\""  % a.replace(".apk", ".basic")
        f = open(a.replace(".apk", ".basic"), "w")
        f.write(str(basic))
        f.close()
        print "[*] Saving permission-related features to \"%s\""  % a.replace(".apk", ".perm")
        f = open(a.replace(".apk", ".perm"), "w")
        f.write(str(permissions))
        f.close()
        print "[*] Saving API call features to \"%s\""  % a.replace(".apk", ".api")
        f = open(a.replace(".apk", ".api"), "w")
        f.write(str(apicalls))
        f.close()
        print "[*] Saving all features to \"%s\""  % a.replace(".apk", ".static")
        f = open(a.replace(".apk", ".static"), "w")
        f.write(str(allfeatures))
        f.close()

        counter += 1

    except Exception as e:
        print "Error encountered: %s" % e
        counter += 1
        continue
