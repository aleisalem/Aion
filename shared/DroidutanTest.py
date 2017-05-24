#!/usr/bin/python

# Aion imports
from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *

# Third-party imports
from droidutan import Droidutan

# Python imports
import os, sys, shutil, subprocess, threading

class DroidutanAnalysis(threading.Thread):
    """
    Represents a Droidutan-driven test of an APK
    """
    def __init__(self, threadID, threadName, threadVM, threadTarget, threadDuration=60):
        """
        Initialize the test
        :param threadID: Used to identify the thread
        :type threadID: int
        :param threadName: A unique name given to a thread
        :type threadName: str
        :param threadVM: The Genymotion AVD name and (optionally snapshot) to run the test on
        :type threadVM: tuple
        :param threadTarget: The path to the APK under test
        :type threadTarget: str
        :param threadDuration: The duration of the Droidutan test in seconds (default: 60s)
        :type threadDuration: int
        """
        threading.Thread.__init__(self, name=threadName) 
        self.threadID = threadID
        self.threadName = threadName
        self.threadVM = threadVM
        self.threadTarget = threadTarget
        self.threadDuration = threadDuration

    def run(self):
        """
        Runs the Droidutan test against the [threadTarget] for [threadDuration]
        """
        try:
            # TODO: Step 0 - Restore snapshot and start AVD
            # Step 1. Analyze APK
            #APKType = "malware" if self.threadTarget.find("malware") != -1 else "goodware"
            if verboseON():
                prettyPrint("Analyzing APK: \"%s\"" % self.threadTarget)
            apk, dx, vm = Droidutan.analyzeAPK(self.threadTarget)
            appComponents = Droidutan.extractAppComponents(apk)

            # Step 2. Get the Ip address assigned to the AVD
            getAVDIPCmd = ["VBoxManage", "guestproperty", "enumerate", self.threadVM[0]]
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
            vboxRestoreCmd = ["vboxmanage", "snapshot", self.threadVM[0], "restore", self.threadVM[1]] if len(self.threadVM) == 2 else ""
            vboxPowerOffCmd = ["vboxmanage", "controlvm", self.threadVM[0], "poweroff"]
            genymotionStartCmd = [getGenymotionPlayer(), "--vm-name", self.threadVM[0]]
            genymotionPowerOffCmd = [getGenymotionPlayer(), "--poweroff", "--vm-name", self.threadVM[0]]
            introspyDBName = self.threadTarget.replace(".apk", ".db") #[self.threadTarget.rfind('/'):] # The APK's original name
            adbPullCmd = [adbPath, "-s", adbID, "pull", "/data/data/%s/databases/introspy.db" % appComponents["package_name"], introspyDBName]
            appUninstallCmd = [adbPath, "-s", adbID, "uninstall", appComponents["package_name"]]

            ## Step 4. Prepare the Genymotion virtual Android device
            ## 4.a. Restore vm to given snapshot
            if vboxRestoreCmd != "":
                if verboseON():
                    prettyPrint("Restoring snapshot \"%s\"" % self.threadVM[1], "debug")
                result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                attempts = 1
                while result.lower().find("error") != -1:
                    print result
                # Retry restoring snapshot for 10 times and then exit
                if attempts == 10:
                    prettyPrint("Failed to restore snapshot \"%s\" after 10 attempts. Exiting" % self.threadVM[1], "error")
                    return False
                prettyPrint("Error encountered while restoring the snapshot \"%s\". Retrying ... %s" % (self.threadVM[1], attempts), "warning")
                # Make sure the virtual machine is switched off for, both, genymotion and virtualbox
                subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                # Now attempt restoring the snapshot
                result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                attempts += 1
                time.sleep(1)
                # 4.b. Start the Genymotion Android virtual device
                if verboseON():
                    prettyPrint("Starting the Genymotion machine \"%s\"" % self.threadVM[0], "debug")
                genyProcess = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                if verboseON():
                    prettyPrint("Waiting for machine to boot ...", "debug")
                time.sleep(30)

            # Step 5. Test the APK using Droidutan (Assuming machine is already on)
            prettyPrint("Testing the APK \"%s\" using Droidutan" % appComponents["package_name"])
            # 5.a. Unleash Droidutan
            if not Droidutan.testApp(self.threadTarget, avdSerialno=avdIP, testDuration=int(self.threadDuration), useIntrospy=True, preExtractedComponents=appComponents, allowCrashes=True):
                prettyPrint("An error occurred while testing the APK \"%s\". Skipping" % self.threadTarget, "warning")
                return False
                #subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                #genyProcess.kill()

            # 5.b. Download the introspy.db
            prettyPrint("Downloading the Introspy database to \"%s\"" % introspyDBName)
            subprocess.Popen(adbPullCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

            # 5.c. Uninstall the app
            prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
            subprocess.Popen(appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            

        except Exception as e:
            prettyPrintError(e)

        return True
