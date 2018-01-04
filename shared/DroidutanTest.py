#!/usr/bin/python

# Aion imports
from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *

# Third-party imports
from droidutan import Droidutan
from androguard.session import Session

# Python imports
import os, sys, shutil, subprocess, threading, signal
            #APKType = "malware" if self.threadTarget.find("malware") != -1 else "goodware"
from multiprocessing import Process

class DroidutanAnalysis(Process):
    """
    Represents a Droidutan-driven test of an APK
    """
    def __init__(self, pID, pName, pVM, pTarget, pDuration=60):
        """
        Initialize the test
        :param pID: Used to identify the process
        :type pID: int
        :param pName: A unique name given to a proces
        :type pName: str
        :param pVM: The Genymotion AVD name to run the test on
        :type pVM: str
        :param pTarget: The path to the APK under test
        :type pTarget: str
        :param pDuration: The duration of the Droidutan test in seconds (default: 60s)
        :type pDuration: int
        """
        Process.__init__(self, name=pName) 
        self.processID = pID
        self.processName = pName
        self.processVM = pVM
        self.processTarget = pTarget
        self.processDuration = pDuration

    def run(self):
        """
        Runs the Droidutan test against the [processTarget] for [processDuration]
        """
        try:
            # A timer to guarante the process exits 
            if verboseON():
                prettyPrint("Setting timer for %s seconds" % str(float(self.processDuration)*5.0), "debug")
            t = threading.Timer(float(self.processDuration)*5.0, self.stop)
            t.start()
            # Step 1. Analyze APK
            if verboseON():
                prettyPrint("Analyzing APK: \"%s\"" % self.processTarget, "debug")
            apk, dx, vm = Droidutan.analyzeAPK(self.processTarget)
            if not apk:
                prettyPrint("Could not retrieve an APK to analyze. Skipping", "warning")
                return False
            # 1.a. Extract app components
            appComponents = Droidutan.extractAppComponents(apk)

            # Step 2. Get the Ip address assigned to the AVD
            getAVDIPCmd = ["VBoxManage", "guestproperty", "enumerate", self.processVM]
            avdIP = ""
            result = subprocess.Popen(getAVDIPCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0].replace(' ', '')
            if result.lower().find("error") != -1:
                prettyPrint("Unable to retrieve the IP address of the AVD", "error")
                print result
                return False
            index = result.find("androvm_ip_management,value:")+len("androvm_ip_management,value:")
            while result[index] != ',':
                avdIP += result[index]
                index += 1
            adbID = "%s:5555" % avdIP

            # Step 3. Define frequently-used commands
            adbPath = getADBPath()
            dumpLogcatCmd = [adbPath, "-s", adbID, "logcat", "-d"]
            clearLogcatCmd = [adbPath, "-s", adbID, "-c"]

            # Step 4. Test the APK using Droidutan (Assuming machine is already on)
            prettyPrint("Clearing device log before test")
            subprocess.Popen(clearLogcatCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            prettyPrint("Testing the APK \"%s\" using Droidutan" % appComponents["package_name"])
            # 4.a. Unleash Droidutan
            success = Droidutan.testApp(self.processTarget, avdSerialno=avdIP, testDuration=int(self.processDuration), preExtractedComponents=appComponents, allowCrashes=False)
            if not success:
                prettyPrint("An error occurred while testing the APK \"%s\". Skipping" % self.processTarget, "warning")
                return False

            # 5. Dump the system log to file
            logcatFile = open(self.processTarget.replace(".apk", ".log"), "w")
            prettyPrint("Dumping logcat")
            subprocess.Popen(dumpLogcatCmd, stderr=subprocess.STDOUT, stdout=logcatFile).communicate()[0]
            logcatFile.close()

            # 6. Filter droidmon entries related to the APK under test
            prettyPrint("Retrieving \"Droidmon-apimonitor-%s\" tags from log" % appComponents["package_name"])
            catlog = subprocess.Popen(("cat", logcatFile.name), stdout=subprocess.PIPE)
            try:
                output = subprocess.check_output(("grep", "-i", "droidmon-apimonitor-%s" % appComponents["package_name"]), stdin=catlog.stdout)
            except subprocess.CalledProcessError as cpe:
                prettyPrint("Could not find the tag \"droidmon-apimonitor-%s in the logs" % appComponents["package_name"], "warning")
                return True
            logFile = open("%s_filtered.log" % self.processTarget.replace(".apk", ""), "w")
            logFile.write(output)
            logFile.close()
            os.remove(logcatFile.name)           
 
        except Exception as e:
            prettyPrintError(e)

        return True


    def stop(self):
        """
        Stops this analysis process
        """
        try:
            prettyPrint("Stopping the analysis process \"%s\" on \"%s\"" % (self.processName, self.processVM), "warning")
            os.kill(os.getpid(), signal.SIGTERM)

        except Exception as e:
            prettyPrintError(e)

        return True


