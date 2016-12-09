#!/usr/bin/python

import Aion.conf.config
from Aion.utils.graphics import *

def getProjectDir():
    """Returns the absolute path of the project"""
    return config.Aion_DIR

def loggingON():
    """ Returns whether logging is on """
    on = True if config.LOGGING == "ON" else False
    return on

def verboseON():
    """ Returns whether verbose debug messages should be displayed """
    verbose = True if config.VERBOSE == "ON" else False
    return verbose

def loadDirs():
    """ Loads the directories' paths from the config.py file """
    return {"Aion_DIR": config.Aion_DIR, "DOWNLOADS_DIR": config.DOWNLOADS_DIR}

def loadPlayStoreConfig():
    """ Loads the necessary configurations for crawling the Play Store """
    return {"LANG": config.LANG, "ANDROID_ID": config.ANDROID_ID, "GOOGLE_LOGIN": config.GOOGLE_LOGIN, "GOOGLE_PASSWORD": config.GOOGLE_PASSWORD, "AUTH_TOKEN": config.AUTH_TOKEN}

def logEvent(msg):
    """ Logs a message to the global log file as per config.py """
    try:
        if config.LOGGING == "ON":
            open(config.LOG_FILE, "a").write("%s\n" % msg)
        else:
            prettyPrint("Cannot log event. Logging is switched OFF", "warning")
    except Exception as e:
        prettyPrintError(e)
        return False

    return True