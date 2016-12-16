#!/usr/bin/python

# Python modules
import sys, os, shutil, glob, io

# Aion modules
from Aion.utils.graphics import *
from Aion.utils.data import *
from Aion.shared.constants import *


# Third-party libraries
from androguard.session import Session
from androguard.misc import AXMLPrinter

class Garfield():
    """ Garfield is a lazy stimulation engine based on fuzzing via Monkey(runner) and Genymotion """
    
    def __init__(self, pathToAPK, APKType="goodware"):
        if not os.path.exists(pathToAPK):
             raise APKNotFoundException("APK file \"%s\" does not exist" % pathToAPK)
        self.APKPath = pathToAPK
        self.APK, self.DEX, self.VMAnalysis = None, None, None
        self.activitiesInfo, self.servicesInfo, self.receiversInfo = {}, {}, {}
        self.runnerScript = ""
        self.APKType = APKType
   
    def analyzeAPK(self):
        """ Uses androguard to retrieve metadata about the app e.g. activities, permissions, intent filters, etc. """
        try:
            prettyPrint("Analyzing app")
            logEvent("Analyzing app: \"%s\"" % self.APKPath)
            # 1. Load the APK using androguard
            analysisSession = Session()
            analysisSession.add(self.APKPath, open(self.APKPath).read())
            # 2. Retrieve handles to APK and its dex code
            self.APK = analysisSession.analyzed_apk.values()[0]
            self.DEX = analysisSession.analyzed_dex.values()[0][0]
            self.VMAnalysis = analysisSession.analyzed_dex.values()[0][1]
            # 3. Retrieve information for each activity
            prettyPrint("Analyzing activities")
            self.activitiesInfo = analyzeActivities(self.APK, self.DEX)
            # 4. Do the same for services and broadcast receivers
            prettyPrint("Analyzing services")
            self.servicesInfo = analyzeServices(self.APK, self.DEX)
            prettyPrint("Analyzing broadcast receivers")
            self.receiversInfo = analyzeReceivers(self.APK, self.DEX)
           
        except Exception as e:
            prettyPrintError(e)
            return False

        prettyPrint("Success")
        return True

    def generateRunnerScript(self, runningTime=60):
        """Generates a python script to be run by Monkeyrunner"""
        try:
            # Check whether the APK has been analyzed first
            if not self.APK:
                prettyPrint("APK needs to be analyzed first", "warning")
                return False

            self.runnerScript = "%s/files/scripts/%s.py" % (getProjectDir(), getRandomAlphaNumeric())
            monkeyScript = open(self.runnerScript, "w")
            # Preparation
            monkeyScript.write("#!/usr/bin/python\n\n")
            monkeyScript.write("from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice\n")
            monkeyScript.write("import time, os, random\n\n")
            monkeyScript.write("keyEvents = %s\n" % keyEvents)
            monkeyScript.write("keyEventTypes = [MonkeyDevice.UP, MonkeyDevice.DOWN, MonkeyDevice.DOWN_AND_UP]\n")
            monkeyScript.write("activityActions = %s\n" % activityActions)
            monkeyScript.write("activities = %s\n" % self.activitiesInfo)
            monkeyScript.write("services = %s\n" % self.servicesInfo)
            monkeyScript.write("receivers = %s\n\n" % self.receiversInfo)
            # Connect to the current device and install package
            monkeyScript.write("print \"[*] Connecting to device.\"\n")
            monkeyScript.write("device = MonkeyRunner.waitForConnection()\n")
            monkeyScript.write("print \"[*] Installing package %s\"\n" % self.APK.package)
            monkeyScript.write("device.installPackage('%s')\n" % self.APKPath)
            monkeyScript.write("package = '%s'\n" % self.APK.package)
            # Configure introspy for hooking and monitoring
            monkeyScript.write("print \"[*] Configuring Introspy\"\n")
            monkeyScript.write("device.shell(\"echo 'GENERAL CRYPTO,KEY,HASH,FS,IPC,PREF,URI,WEBVIEW,SSL' > /data/data/%s/introspy.config\" % package)\n")
            monkeyScript.write("device.shell(\"chmod 664 /data/data/%s/introspy.config\" % package)\n")
            # Start app
            #monkeyScript.write("mainActivity = '%s'\n" % APK.APK.get_main_activity()) 
            #monkeyScript.write("device.startActivity(component=package + '/' + mainActivity)\n")
            # Starting the fuzzing phase for [runningTime] seconds
            monkeyScript.write("endTime = time.time() + %s\n" % runningTime)
            monkeyScript.write("print \"[*] Fuzzing app for %s seconds\"\n" % runningTime)
            monkeyScript.write("while time.time() < endTime:\n")
            # 1. Choose a random component
            monkeyScript.write("\tcomponentType = [\"activity\", \"service\", \"receiver\"][random.randint(0,2)]\n")
            # 2.a. Activities
            monkeyScript.write("\tif componentType == \"activity\":\n")
            monkeyScript.write("\t\tcurrentActivity = activities.keys()[random.randint(0,len(activities)-1)]\n")
            monkeyScript.write("\t\tprint \"[*] Starting activity: %s\" % currentActivity\n")
            monkeyScript.write("\t\tdevice.startActivity(component=package + '/' + currentActivity)\n")
            # Choose an action 
            monkeyScript.write("\t\tcurrentAction = activityActions[random.randint(0,len(activityActions)-1)]\n")
            monkeyScript.write("\t\tprint \"[*] Current action: %s\" % currentAction \n")
            # Touch in a random X,Y position on the screen
            monkeyScript.write("\t\tif currentAction == \"touch\":\n")
            monkeyScript.write("\t\t\twidth, height = int(device.getProperty(\"display.width\")), int(device.getProperty(\"display.height\"))\n")
            monkeyScript.write("\t\t\tX, Y = random.randint(0, width-1), random.randint(0, height-1)\n")
            monkeyScript.write("\t\t\tprint \"[*] Touching screen at (%s,%s)\" % (X,Y)\n")
            monkeyScript.write("\t\t\tdevice.touch(X, Y, keyEventTypes[random.randint(0,2)])\n")
            # Type something random
            monkeyScript.write("\t\telif currentAction == \"type\":\n")
            monkeyScript.write("\t\t\ttext = \"%s\"\n" % getRandomString(random.randint(0,100)))
            monkeyScript.write("\t\t\tprint \"[*] Typing %s\" % text\n")
            monkeyScript.write("\t\t\tdevice.type(\"text\")\n")
            # Press a random key up/down
            monkeyScript.write("\t\telif currentAction == \"press\":\n")
            monkeyScript.write("\t\t\taction = keyEvents[random.randint(0, len(keyEvents)-1)]\n")
            monkeyScript.write("\t\t\taType =  keyEventTypes[random.randint(0,2)]\n")
            monkeyScript.write("\t\t\tprint \"[*] Pressing: %s as %s\" % (action, aType)\n")
            monkeyScript.write("\t\t\tdevice.press(action, aType)\n")
            # Randomly drag the screen
            monkeyScript.write("\t\telif currentAction == \"drag\":\n")
            monkeyScript.write("\t\t\twidth, height = int(device.getProperty(\"display.width\")), int(device.getProperty(\"display.height\"))\n")
            monkeyScript.write("\t\t\tstart = (random.randint(0, width-1), random.randint(0, height-1))\n")
            monkeyScript.write("\t\t\tend = (random.randint(0, width-1), random.randint(0, height-1))\n")
            monkeyScript.write("\t\t\tprint \"[*] Dragging screen from %s to %s\" % (start, end)\n")
            monkeyScript.write("\t\t\tdevice.drag(start, end)\n")
            # 2.b.Services
            monkeyScript.write("\telif componentType == \"service\":\n")
            monkeyScript.write("\t\tcurrentService = services.keys()[random.randint(0, len(services)-1)]\n")
            monkeyScript.write("\t\tprint \"[*] Starting Service: %s\" % currentService\n")
            monkeyScript.write("\t\tif \"intent-filters\" in services[currentService].keys():\n")
            monkeyScript.write("\t\t\tif \"action\" in services[currentService][\"intent-filters\"].keys():\n")
            monkeyScript.write("\t\t\t\tintentAction = services[currentService][\"intent-filters\"][\"action\"][0]\n")
            monkeyScript.write("\t\t\t\tprint \"[*] Broadcasting intent: %s\" % intentAction\n")
            monkeyScript.write("\t\t\t\tdevice.broadcastIntent(currentService, intentAction)\n")
            # 2.c. Broadcast receivers
            monkeyScript.write("\telif componentType == \"receiver\":\n")
            monkeyScript.write("\t\tcurrentReceiver = receivers.keys()[random.randint(0, len(receivers)-1)]\n")
            monkeyScript.write("\t\tprint \"[*] Starting Receiver: %s\" % currentReceiver\n")
            monkeyScript.write("\t\tif \"intent-filters\" in receivers[currentReceiver].keys():\n")
            monkeyScript.write("\t\t\tif \"action\" in receivers[currentReceiver][\"intent-filters\"].keys():\n")
            monkeyScript.write("\t\t\t\tintentAction = receivers[currentReceiver][\"intent-filters\"][\"action\"][0]\n")
            monkeyScript.write("\t\t\t\tprint \"[*] Broadcasting intent: %s\" % intentAction\n")
            monkeyScript.write("\t\t\t\tdevice.broadcastIntent(currentReceiver, intentAction)\n")
            # Sleep for 0.5 a second
            monkeyScript.write("\ttime.sleep(0.5)\n")
            # TODO: Uninstall package (Can crash app if it's not done with computations)
            #monkeyScript.write("device.removePackage(package)\n")
        
        except Exception as e:
            prettyPrintError(e)
            return False

        return True    
def analyzeActivities(APK, DEX):
    """ Analyzes the passed APK and DEX objects to retrieve the elements within every activity """
    try:
        info = {}
        for activity in APK.get_activities():
            info[activity] = {}
            # 1. Add the intent filters
            info[activity]["intent-filters"] = APK.get_intent_filters("activity", activity)
            # 2. Get all classes belonging to current activity
            allClasses, tempList, layoutFiles = DEX.get_classes(), [], []
            # 2.a. Get all classes that inherit class "Activity" i.e. corresponding to an activity 
            for c in allClasses:
                if c.get_superclassname().lower().find("activity") != -1:
                    tempList.append(c)
            # 2.b. Get classes belonging to CURRENT activity
            info[activity]["classes"] = []
            for c in tempList:
                if c.get_name()[1:-1].replace('/','.') == activity:
                    info[activity]["classes"].append(c)
                    if loggingON():
                        prettyPrint("Activity: %s, class: %s" % (activity, c), "debug")
            
            # 3. Get UI elements in every activity
            # 3.a. Identify the layout file's ID in the class' setContentView function call
            source = info[activity]["classes"][0].get_source()
            info[activity].pop("classes") # TODO: Do we really need a reference to the class object?
            index1 = source.find("void onCreate(")
            index2 = source.find("setContentView(", index1) + len("setContentView(")
            layoutID = ""
            while str.isdigit(source[index2]):
                layoutID += source[index2]
                index2 += 1
            # layoutID retrieved?
            if len(layoutID) < 1:
                prettyPrint("Could not retrieve layout ID from activity class. Skipping", "warning")
                continue
            # 3.b. Look for the corresponding layout name in the R$layout file
            layoutClass = DEX.get_class(str("L%s/R$layout;" % APK.package.replace('.','/')))
            if layoutClass:
                layoutContent = layoutClass.get_source() 
                eIndex = layoutContent.find(layoutID)
                sIndex = layoutContent.rfind("int", 0, eIndex)
                layoutName = layoutContent[sIndex+len("int"):eIndex].replace(' ','').replace('=','')
            else:
                # No layout class was found: Check the public.xml file
                prettyPrint("Could not find a \"R$layout\" class. Checking \"public.xml\"", "warning")
                apkResources = APK.get_android_resources()
                publicResources = apkResources.get_public_resources(APK.package).split('\n')
                layoutIDHex = hex(int(layoutID))
                for line in publicResources:
                    if line.find(layoutIDHex) != -1:
                        sIndex = line.find("name=\"") + len("name=\"")
                        eIndex = line.find("\"", sIndex)
                        layoutName = line[sIndex:eIndex]
            # 3.c. Retrieve layout file and get XML object
            if len(layoutName) < 1:
                prettyPrint("Could not retrieve a layout file for \"%s\". Skipping" % activity, "warning")
            else:
                if loggingON():
                    prettyPrint("Retrieving UI elements from %s.xml" % layoutName, "debug")
                info[activity]["elements"] = _parseActivityLayout("res/layout/%s.xml" % layoutName, APK)
                
    except Exception as e:
        prettyPrintError(e)
        return {}

    return info

def analyzeServices(APK, DEX):
    """ Analyzes the passed APK and DEX objects to retrieve information about an app's services """
    try:
        info = {}
        for service in APK.get_services():
            info[service] = {}
            info[service]["intent-filters"] = APK.get_intent_filters("service", service)

    except Exception as e:
        prettyPrintError(e)
        return {}

    return info

def analyzeReceivers(APK, DEX):
    """ Analyzes the passed APK and DEX objects to retrieve information about an app's broadcast receivers """
    try:
        info = {}
        for receiver in APK.get_receivers():
            info[receiver] = {}
            info[receiver]["intent-filters"] = APK.get_intent_filters("receiver", receiver)

    except Exception as e:
        prettyPrintError(e)
        return {}

    return info

def _parseActivityLayout(layoutFilePath, APK):
    """ Parses an XML layout file of an activity and returns information about the found elements """
    try:
        elements = {}
        # Read the contents of the layout file
        activityXML = AXMLPrinter(APK.get_file(layoutFilePath)).get_xml_obj()
        logEvent("Parsing the XML layout %s" % layoutFilePath)
        # Iterate over the elements and parse them
        for currentNode in activityXML.firstChild.childNodes:
            if currentNode.nodeName == "Button" or currentNode.nodeName == "ImageButton" or currentNode.nodeName == "RadioButton":
                # Handling buttons
                attr = {}
                eID = currentNode.attributes["android:id"].value
                attr["type"] = currentNode.nodeName
                if "android:onClick" in currentNode.attributes.keys():
                    attr["onclick"] = currentNode.attributes["android:onClick"].value
                if "android:visibility" in currentNode.attributes.keys():
                    attr["visibility"] = currentNode.attributes["android:visibility"].value
                if "android:clickable" in currentNode.attributes.keys():
                    attr["clickable"] = currentNode.attributes["android:clickable"].value
                if "android:longClickable" in currentNode.attributes.keys():
                    attr["longclickable"] = currentNode.attributes["android:longClickable"].value
                elements[eID] = attr
            elif currentNode.nodeName == "CheckBox" or currentNode.nodeName == "CheckedTextView":
                # Handling checkbox-like elements
                attr = {}
                eID = currentNode.attributes["android:id"].value
                attr["type"] = currentNode.nodeName
                if "android:onClick" in currentNode.attributes.keys():
                    attr["onclick"] = currentNode.attributes["android:onClick"].value
                if "android:visibility" in currentNode.attributes.keys():
                    attr["visibility"] = currentNode.attributes["android:visibility"].value
                if "android:checked" in currentNode.attributes.keys():
                    attr["checked"] = currentNode.attributes["android:checked"].value
                elements[eID] = attr
            elif currentNode.nodeName == "DatePicker":
                # Handling date pickers
                attr = {}
                eID = currentNode.attributes["android:id"].value
                attr["type"] = currentNode.nodeName
                if "android:minDate" in currentNode.attributes.keys():
                    attr["mindate"] = currentNode.attributes["android:minDate"]
                if "android:maxDate" in currentNode.attributes.keys():
                    attr["maxDate"] = currentNode.attributes["android:maxDate"]
                elements[eID] = attr
            elif currentNode.nodeName == "EditText":
                # Handling edit texts
                attr = {}
                eID = currentNode.attributes["android:id"].value
                attr["type"] = currentNode.nodeName
                if "android:editable" in currentNode.attributes.keys():
                    attr["editable"] = currentNode.attributes["android:editable"]
                if "android:inputType" in currentNode.attributes.keys():
                    attr["inputtype"] = currentNode.attributes["android:inputType"]
                elements[eID] = attr
            #elif currentNode.nodeName == "NumberPicker":
            elif currentNode.nodeName == "RadioGroup":
                # Handle radio group
                # 1. Get radio buttons
                buttons = currentNode.childNodes
                for button in buttons:
                    attr = {}
                    eID = currentNode.attributes["android:id"].value
                    attr["type"] = currentNode.nodeName
                    if "android:onClick" in currentNode.attributes.keys():
                        attr["onclick"] = currentNode.attributes["android:onClick"].value
                    if "android:visibility" in currentNode.attributes.keys():
                        attr["visibility"] = currentNode.attributes["android:visibility"].value
                    if "android:clickable" in currentNode.attributes.keys():
                        attr["clickable"] = currentNode.attributes["android:clickable"].value
                    if "android:longClickable" in currentNode.attributes.keys():
                        attr["longclickable"] = currentNode.attributes["android:longClickable"].value
                    elements[eID] = attr

            #elif currentNode.nodeName == "Spinner":

    except Exception as e:
        prettyPrintError(e)
        return {}

    return elements

