#!/usr/bin/python

from Aion.conf import config

def getAionDBPath():
    """Returns the path to the Aion DB"""
    return config.AION_DB

def getAionDBRecovery():
    """Returns the path to the Aion DB recovery script"""
    return config.DB_RECOVERY

def getHashesDBPath():
    """Returns the path to the hashes DB for quick lookup of app package names"""
    return config.HASHES_DB

def getSDKDir():
    """Returns the Android SDK directory path"""
    return config.ANDROID_SDK

def getADBPath():
    """Returns the path to the adb tool"""
    return config.ANDROID_ADB

def getGenymotionPlayer():
    """Returns the path to the Genymotion VM player"""
    return config.GENYMOTION_PLAYER

def getProjectDir():
    """Returns the absolute path of the project"""
    return config.AION_DIR

def loggingON():
    """Returns whether logging is on"""
    on = True if config.LOGGING == "ON" else False
    return on

def verboseON():
    """Returns whether verbose debug messages should be displayed"""
    verbose = True if config.VERBOSE == "ON" else False
    return verbose

def loadDirs():
    """Loads the directories' paths from the config.py file"""
    return {"Aion_DIR": config.Aion_DIR, "DOWNLOADS_DIR": config.DOWNLOADS_DIR, "ANDROID_SDK": config.ANDROID_SDK}

def loadPlayStoreConfig():
    """Loads the necessary configurations for crawling the Play Store"""
    return {"LANG": config.LANG, "ANDROID_ID": config.ANDROID_ID, "GOOGLE_LOGIN": config.GOOGLE_LOGIN, "GOOGLE_PASSWORD": config.GOOGLE_PASSWORD, "AUTH_TOKEN": config.AUTH_TOKEN}

def logEvent(msg):
    """Logs a message to the global log file as per config.py"""
    if config.LOGGING == "ON":
        open(config.LOG_FILE, "a").write("%s\n" % msg)

    return True
