#!/usr/bin/python

# Aion imports
from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *

# Third-party software imports
from androguard.session import Session

# Python imports
import os, sys, shutil, subprocess, threading, signal
from multiprocessing import Process

class DroidbotAnalysis(Process):
    """
    Represents a Droidutan-driven test of an APK
    """
    def __init__(self, pID, pName, pVM, pTarget, pSt="", pDuration=60):
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
        :param pSt: The snapshot of the AVD in case restoring is needed
        :type pSt: str
        :param pDuration: The duration of the Droidutan test in seconds (default: 60s)
        :type pDuration: int
        """
        Process.__init__(self, name=pName) 
        self.processID = pID
        self.processName = pName
        self.processVM = pVM
        self.processTarget = pTarget
        self.processSnapshot = pSt
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
            #APKType = "malware" if self.processTarget.find("malware") != -1 else "goodware"
            if verboseON():
                prettyPrint("Analyzing APK: \"%s\"" % self.processTarget, "debug")
            s = Session()
            s.add(self.processTarget, open(self.processTarget).read())
            if len(s.analyzed_apk.values()) > 0:
                apk = s.analyzed_apk.values()[0]
                if type(apk) == list:
                    apk = s.analyzed_apk.values()[0][0]
            else:
                prettyPrint("Could not retrieve an APK to analyze. Skipping", "warning")
                return False

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
            droidbotOut = self.processTarget.replace(".apk", "_droidbot")
            droidbotCmd = ["droidbot", "-d", adbID, "-a", self.processTarget, "-o", droidbotOut, "-timeout", str(self.processDuration), "-random", "-keep_env", "-grant_perm"]

            # Step 4. Test the APK using Droidbot (Assuming machine is already on)
            prettyPrint("Testing the APK \"%s\" using Droidbot" % apk.package)
            # 4.a. Start Droidbot
            status = subprocess.Popen(droidbotCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

            # 4.b. Check for existence of output directory
            if not os.path.exists(droidbotOut):
                prettyPrint("No output folder found for \"%s\"" % self.processTarget, "warning")
                return False

            # 4.c. Filter the logcat dumped by droidbot
            logFile = open("%s/logcat_filtered.log" % droidbotOut, "w")
            catlog = subprocess.Popen(("cat", "%s/logcat.txt" % droidbotOut), stdout=subprocess.PIPE)
            output = subprocess.check_output(("grep", "-i", "droidmon-apimonitor-%s" % apk.package), stdin=catlog.stdout)
            logFile.write(output)
            logFile.close()
 
        except subprocess.CalledProcessError as cpe:
            prettyPrint("Unable to find the tag \"Droidmon-apimonitor-%s\" in the log file" % apk.package, "warning")
        except Exception as e:
            prettyPrintError(e)
            return False
        
        return True

    def stop(self):
        """
        Stops this analysis process after uninstalling the app under test
        """
        try:
            prettyPrint("Stopping the analysis process \"%s\" on \"%s\". Restoring snapshot \"%s\"" % (self.processName, self.processVM, self.processSnapshot), "warning")
            os.kill(os.getpid(), signal.SIGTERM)
            # Restore snapshot because that is probably not a good sign
            if self.processSnapshot != "":
                restoreVirtualBoxSnapshot(self.processVM, self.processSnapshot)

        except Exception as e:
            prettyPrintError(e)

        return True


