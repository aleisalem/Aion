#!/usr/bin/python

# Aion imports
from Aion.utils.data import *
from Aion.utils.graphics import *
from Aion.utils.misc import *

# Third-party imports
from droidutan import Droidutan

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
        :param pVM: The Genymotion AVD name and (optionally snapshot) to run the test on
        :type pVM: tuple
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
            #APKType = "malware" if self.processTarget.find("malware") != -1 else "goodware"
            if verboseON():
                prettyPrint("Analyzing APK: \"%s\"" % self.processTarget, "debug")
            apk, dx, vm = Droidutan.analyzeAPK(self.processTarget)
            appComponents = Droidutan.extractAppComponents(apk)

            # Step 2. Get the Ip address assigned to the AVD
            getAVDIPCmd = ["VBoxManage", "guestproperty", "enumerate", self.processVM[0]]
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

            if verboseON():
                prettyPrint("Waiting for machine to boot ...", "debug")                
            os.system("adb -s %s wait-for-device" % avdIP)

            # Step 3. Define frequently-used commands
            adbPath = getADBPath()
            vboxRestoreCmd = ["vboxmanage", "snapshot", self.processVM[0], "restore", self.processVM[1]] if len(self.processVM) == 2 else ""
            vboxPowerOffCmd = ["vboxmanage", "controlvm", self.processVM[0], "poweroff"]
            genymotionStartCmd = [getGenymotionPlayer(), "--vm-name", self.processVM[0]]
            genymotionPowerOffCmd = [getGenymotionPlayer(), "--poweroff", "--vm-name", self.processVM[0]]
            introspyDBName = self.processTarget.replace(".apk", ".db") #[self.threadTarget.rfind('/'):] # The APK's original name
            self.adbPullCmd = [adbPath, "-s", adbID, "pull", "/data/data/%s/databases/introspy.db" % appComponents["package_name"], introspyDBName]
            self.appUninstallCmd = [adbPath, "-s", adbID, "uninstall", appComponents["package_name"]]

            ## Step 4. Prepare the Genymotion virtual Android device
            ## 4.a. Restore vm to given snapshot
            if vboxRestoreCmd != "":
                # Make sure the virtual machine is switched off for, both, genymotion and virtualbox
                subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                # Now attempt restoring the snapshot
                result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                if verboseON():
                    prettyPrint("Restoring snapshot \"%s\"" % self.processVM[1], "debug")
                result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                attempts = 1
                while result.lower().find("error") != -1:
                    print result
                    # Retry restoring snapshot for 10 times and then exit
                    if attempts == 10:
                        prettyPrint("Failed to restore snapshot \"%s\" after 10 attempts. Exiting" % self.procesVM[1], "error")
                        return False
                    prettyPrint("Error encountered while restoring the snapshot \"%s\". Retrying ... %s" % (self.processVM[1], attempts), "warning")
                    # Make sure the virtual machine is switched off for, both, genymotion and virtualbox
                    subprocess.Popen(vboxPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                    # Now attempt restoring the snapshot
                    result = subprocess.Popen(vboxRestoreCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                    attempts += 1
                    time.sleep(1)

                # 4.b. Start the Genymotion Android virtual device
                if verboseON():
                    prettyPrint("Starting the Genymotion machine \"%s\"" % self.processVM[0], "debug")
                genyProcess = subprocess.Popen(genymotionStartCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)


            # Step 5. Test the APK using Droidutan (Assuming machine is already on)
            prettyPrint("Testing the APK \"%s\" using Droidutan" % appComponents["package_name"])
            # 5.a. Unleash Droidutan
            success = Droidutan.testApp(self.processTarget, avdSerialno=avdIP, testDuration=int(self.processDuration), useIntrospy=True, preExtractedComponents=appComponents, allowCrashes=True)
            if not success:
                prettyPrint("An error occurred while testing the APK \"%s\". Skipping" % self.processTarget, "warning")
                # 5.b. Download the introspy.db
                prettyPrint("Downloading the Introspy database to \"%s\"" % introspyDBName, "warning")
                subprocess.Popen(self.adbPullCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                # 5.c. Uninstall the app
                prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID), "warning")
                subprocess.Popen(self.appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                #subprocess.Popen(genymotionPowerOffCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                #genyProcess.kill()
                return False

            # 5.d. Download the introspy.db
            prettyPrint("Downloading the Introspy database to \"%s\"" % introspyDBName)
            subprocess.Popen(self.adbPullCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

            # 5.e. Uninstall the app
            prettyPrint("Uninstalling \"%s\" from \"%s\"" % (appComponents["package_name"], adbID))
            subprocess.Popen(self.appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            
        except Exception as e:
            prettyPrintError(e)

        return True


    def stop(self):
        """
        Stops this analysis process after downloading the introspy database and uninstalling the app under test
        """
        try:
            prettyPrint("Stopping the analysis process \"%s\" on \"%s\"" % (self.processName, self.processVM), "warning")
            #prettyPrint("Downloading the Introspy database", "warning")
           # subprocess.Popen(self.adbPullCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
            # Uninstall the app
            #prettyPrint("Uninstalling app", "warning")
            #subprocess.Popen(self.appUninstallCmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
            os.kill(os.getpid(), signal.SIGTERM)
            #self.terminate() # Terminate process: Is it better/cleaner?

        except Exception as e:
            prettyPrintError(e)

        return True


