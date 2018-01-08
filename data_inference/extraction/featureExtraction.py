#!/usr/bin/python

from Aion.shared.constants import *
from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.conf.config import *

from androguard.session import Session
import numpy

import os, json, threading, re

def returnEmptyFeatures():
    """
    A dummy function used by timers to return empty feature vectors (lists)
    """
    prettyPrint("Analysis timeout. Returning empty feature vector", "warning")
    return []

def extractStaticFeatures(apkPath):
    """Extracts static numerical features from APK using Androguard"""
    try:
        features = [[], [], [], []] # Tuples are immutable
        if os.path.exists(apkPath.replace(".apk",".static")):
            prettyPrint("Found a pre-computed static features file")
            bFeatures, pFeatures, aFeatures, allFeatures = [], [], [], []
            try:
                possibleExtensions = [".basic", ".perm", ".api", ".static"]
                for ext in possibleExtensions:
                    if os.path.exists(apkPath.replace(".apk", ext)):
                        content = open(apkPath.replace(".apk", ext)).read()
                        if len(content) > 0:
                            features[possibleExtensions.index(ext)] = [float(f) for f in content[1:-1].split(',') if len(f) > 0]

                return tuple(features)

            except Exception as e:
                prettyPrintError(e)
                prettyPrint("Could not extract features from \".static\" file. Continuing as usual", "warning")
        if verboseON():
            prettyPrint("Starting analysis on \"%s\"" % apkPath, "debug")
        analysisSession = Session()
        if not os.path.exists(apkPath):
            prettyPrint("Could not find the APK file \"%s\"" % apkPath, "warning")
            return [], [], [], []
        # 1. Analyze APK and retrieve its components
        #t = threading.Timer(300.0, returnEmptyFeatures) # Guarantees not being stuck on analyzing an APK
        #t.start()
        analysisSession.add(apkPath, open(apkPath).read())
        if type(analysisSession.analyzed_apk.values()) == list:
            apk = analysisSession.analyzed_apk.values()[0][0]
        else:
            apk = analysisSession.analyzed_apk.values()[0]
        dex = analysisSession.analyzed_dex.values()[0][0]
        vm = analysisSession.analyzed_dex.values()[0][1]
        # 2. Add features to the features vector
        basicFeatures, permissionFeatures, apiCallFeatures, allFeatures = [], [], [], []
        # 2.a. The APK-related features
        if verboseON():
            prettyPrint("Extracting basic features", "debug")
        minSDKVersion = 0.0 if not apk.get_min_sdk_version() else float(apk.get_min_sdk_version())
        maxSDKVersion = 0.0 if not apk.get_max_sdk_version() else float(apk.get_max_sdk_version())
        basicFeatures.append(minSDKVersion)
        basicFeatures.append(maxSDKVersion)
        basicFeatures.append(float(len(apk.get_activities()))) # No. of activities
        basicFeatures.append(float(len(apk.get_services()))) # No. of services
        basicFeatures.append(float(len(apk.get_receivers()))) # No. of broadcast receivers
        basicFeatures.append(float(len(apk.get_providers()))) # No. of providers
        # 2.b. Harvest permission-related features
        if verboseON():
            prettyPrint("Extracting permissions-related features", "debug")
        aospPermissions = float(len(apk.get_requested_aosp_permissions())) # Android permissions requested by the app
        declaredPermissions = float(len(apk.get_declared_permissions())) # Custom permissions declared by the app
        dangerousPermissions = float(len([p for p in apk.get_requested_aosp_permissions_details().values() if p["protectionLevel"] == "dangerous"]))
        totalPermissions = float(len(apk.get_permissions()))
        permissionFeatures.append(totalPermissions) # No. of permissions
        if totalPermissions > 0:
            permissionFeatures.append(aospPermissions/totalPermissions) # AOSP permissions : Total permissions
            permissionFeatures.append(declaredPermissions/totalPermissions) # Third-party permissions : Total permissions
            permissionFeatures.append(dangerousPermissions/totalPermissions) # Dangerous permissions : Total permissions
        else:
            permissionFeatures.append(0.0)
            permissionFeatures.append(0.0)
            permissionFeatures.append(0.0)
        # 2.c. The DEX-related features (API calls)
        if verboseON():
            prettyPrint("Extracting API calls from dex code", "debug")
        apiCallFeatures.append(float(len(dex.get_classes()))) # Total number of classes
        apiCallFeatures.append(float(len(dex.get_strings()))) # Total number of strings
        apiCategories = sensitiveAPICalls.keys()
        apiCategoryCount = [0.0] * len(apiCategories)
        for c in dex.classes.get_names():
            currentClass = dex.get_class(c)
            if not currentClass:
                continue
            code = currentClass.get_source()
            if len(code) < 1:
                continue
            for category in apiCategories:
                if code.find(category) != -1:
                    for call in sensitiveAPICalls[category]:
                        apiCategoryCount[apiCategories.index(category)] += float(len(re.findall(call, code)))

        apiCallFeatures += apiCategoryCount

    except Exception as e:
        prettyPrintError(e)
        return [], [], [], []
    
    allFeatures = basicFeatures + permissionFeatures + apiCallFeatures

    return basicFeatures, permissionFeatures, apiCallFeatures, allFeatures


def extractIntrospyFeatures(apkJSONPath):
    """Extracts dynamic features from a JSON-based trace generated by Introspy"""
    try:
        features = []
        if not os.path.exists(apkJSONPath):
            prettyPrint("Could not find the JSON file \"%s\"" % apkJSONPath, "warning")
        else:
            apkJSON = json.loads(open(apkJSONPath).read())
            cryptoCalls, sslCalls, hashCalls = 0.0, 0.0, 0.0 # Crypto group
            fsCalls, prefCalls, uriCalls = 0.0, 0.0, 0.0 # Storage group
            ipcCalls = 0.0 # Ipc group
            webviewCalls = 0.0  # Misc group
            accountManagerCalls, activityCalls, downloadManagerCalls = 0.0, 0.0, 0.0
            contentResolverCalls, contextWrapperCalls, packageInstallerCalls = 0.0, 0.0, 0.0
            sqliteCalls, cameraCalls, displayManagerCalls, locationCalls = 0.0, 0.0, 0.0, 0.0
            audioRecordCalls, mediaRecorderCalls, networkCalls, wifiManagerCalls = 0.0, 0.0, 0.0, 0.0
            powerManagerCalls, smsManagerCalls, toastCalls, classCalls = 0.0, 0.0, 0.0, 0.0
            httpCookieCalls, urlCalls = 0.0, 0.0
            for call in apkJSON["calls"]:
                group, subgroup = call["group"], call["subgroup"]
                if group == "Crypto":
                    cryptoCalls = cryptoCalls + 1 if subgroup == "General crypto" else cryptoCalls
                    hashCalls = hashCalls + 1 if subgroup == "Hash" else hashCalls
                    sslCalls = sslCalls + 1 if subgroup == "Ssl" else sslCalls
                elif group == "Storage":
                    fsCalls = storageCalls + 1 if call["group"] == "Fs" else fsCalls
                    prefCalls = prefCalls + 1 if call["group"] == "Pref" else prefCalls
                    uriCalls = uriCalls + 1 if call["group"] == "Uri" else uriCalls
                elif group == "Ipc":
                    ipcCalls = ipcCalls + 1 if call["group"] == "Ipc" else ipcCalls
                elif group == "Misc":
                    webviewCalls = webviewCalls + 1 if call["group"] == "Webview" else webviewCalls
                elif group.lower().find("custom") != -1:
                    # Handle custom hooks
                    # android.accounts.AccountManager
                    if call["clazz"] == "android.accounts.AccountManager":
                        accountManagerCalls += 1
                    # android.app.Activity
                    elif call["clazz"] == "android.app.Activity":
                        activityCalls += 1
                    # android.app.DownloadManager
                    elif call["clazz"] == "android.app.DownloadManager":
                        downloadManagerCalls += 1 
                    # android.content.ContentResolver
                    elif call["clazz"] == "android.content.ContentResolver":
                        contentResolverCalls += 1
                    # android.content.ContextWrapper
                    elif call["clazz"] == "android.content.ContextWrapper":
                        contextWrapperCalls += 1
                    # android.content.pm.PackageInstaller
                    elif call["clazz"] == "android.content.pm.PackageInstaller":
                        packageInstallerCalls += 1
                    # android.database.sqlite.SQLiteDatabase
                    elif call["clazz"] == "android.database.sqlite.SQLiteDatabase":
                        sqliteCalls += 1
                    # android.hardware.Camera
                    elif call["clazz"] == "android.hardware.Camera":
                        cameraCalls += 1
                    # android.hardware.display.DisplayManager
                    elif call["clazz"] ==  "android.hardware.display.DisplayManager":
                        displayManagerCalls += 1
                    # android.location.Location
                    elif call["clazz"] == "android.location.Location":
                        locationCalls += 1
                    # android.media.AudioRecord
                    elif call["clazz"] == "android.media.AudioRecord":
                        audioRecordCalls += 1
                    # android.media.MediaRecorder
                    elif call["clazz"] == "android.media.MediaRecorder":
                        mediaRecorderCalls += 1
                    # android.net.Network
                    elif call["clazz"] == "android.net.Network":
                        networkCalls += 1
                    # android.net.wifi.WifiManager
                    elif call["clazz"] == "android.net.wifi.WifiManager":
                        wifiManagerCalls += 1
                    # android.os.PowerManager
                    elif call["clazz"] == "android.os.PowerManager":
                        powerManagerCalls += 1
                    # android.telephony.SmsManager
                    elif call["clazz"] == "android.telephony.SmsManager":
                        smsManagerCalls += 1
                    # android.widget.Toast
                    elif call["clazz"] == "android.widget.Toast":
                        toastCalls += 1
                    # java.lang.class
                    elif call["clazz"] == "java.lang.class":
                        classCalls += 1
                    # java.net.HttpCookie
                    elif call["clazz"] == "java.net.HttpCookie":
                        httpCookieCalls += 1
                    # java.net.URL
                    elif call["clazz"] == "java.net.URL":
                        urlCalls += 1

            features.append(cryptoCalls)
            features.append(sslCalls)
            features.append(hashCalls)
            features.append(fsCalls)
            features.append(prefCalls)
            features.append(uriCalls)
            features.append(ipcCalls)
            features.append(webviewCalls)
            features.append(accountManagerCalls)
            features.append(activityCalls)
            features.append(downloadManagerCalls)
            features.append(contentResolverCalls)
            features.append(contextWrapperCalls)
            features.append(packageInstallerCalls)
            features.append(sqliteCalls)
            features.append(cameraCalls)
            features.append(displayManagerCalls)
            features.append(locationCalls)
            features.append(audioRecordCalls)
            features.append(mediaRecorderCalls)
            features.append(networkCalls)
            features.append(wifiManagerCalls)
            features.append(powerManagerCalls)
            features.append(smsManagerCalls)
            features.append(toastCalls)
            features.append(classCalls)
            features.append(httpCookieCalls)
            features.append(urlCalls)

    except Exception as e:
        prettyPrintError(e)
        return []

    return features

def extractDroidmonFeatures(logPath, mode="classes"):
    """
    Extracts numerical features from Droidmon-generated logs
    :param logPath: The path to the JSON-log generated by Droidmon
    :type logPath: str
    :param mode: The type of features to extract (i.e. classes, methods, both)
    :type mode: str
    :return: Two lists depicting the trace found in the log and counts of items it contains
    """
    try:
        features = []
        # Parse the droidmon log
        if not os.path.exists(logPath):
            prettyPrint("Unable to locate \"%s\"" % logPath, "warning")
            return [], []
        lines = open(logPath).read().split('\n')
        if VERBOSE:
            prettyPrint("Successfully retrieved %s lines from log" % len(lines), "debug")
        droidmonLines = [l for l in lines if l.lower().find("droidmon-apimonitor-") != -1]
        # Generate trace from lines
        trace = []
        for line in droidmonLines:
            tmp = line[line.find("{"):].replace('\n','').replace('\r','')
            # Extract class and method
            c, m = "", ""
            #if tmp[0] == '{' and tmp[-1] == '}':
            #    d = eval(tmp)
            #    c, m = d["class"], d["method"]
            #else:
            pattern = "class\":\""
            index = tmp.find(pattern)
            c = tmp[index+len(pattern):tmp.find("\"", index+len(pattern))]
            pattern = "method\":\""
            index = tmp.find(pattern)
            m = tmp[index+len(pattern):tmp.find("\"", index+len(pattern))]
            # Append to trace
            if mode == "classes":
                trace.append(c)
            elif mode == "methods":
                trace.append(m)
            elif mode == "both":
                trace.append("%s.%s" % (c, m))
        # Go over droidmon classes and count occurrences
        source = []
        if mode == "classes":
            source = droidmonDefaultClasses
        elif mode == "methods":
            source = droidmonDefaultMethods
        elif mode == "both":
            source = droidmonDefaultAPIs

        # The loop
        for i in source:
            features.append(trace.count(i))

    except Exception as e:
        prettyPrintError(e)
        return [], []

    return trace, features
