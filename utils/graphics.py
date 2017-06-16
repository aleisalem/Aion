#!/usr/bin/python

# Python modules
import time, sys, os
# Aion modules
from Aion.conf import config
from Aion.utils.data import *
from Aion.utils.misc import *

# Gray, Red, Green, Yellow, Blue, Magenta, Cyan, White, Crimson
colorIndex = [ "30", "31", "32", "33", "34", "35", "36", "37", "38" ]


####################
# Defining Methods #
#################### 
def prettyPrint(msg, mode="info"):
    """ Pretty prints a colored message. "info": Green, "error": Red, "warning": Yellow, "info2": Blue, "output": Magenta, "debug": White """
    if mode == "info":
        color = "32" # Green
    elif mode == "error":
        color = "31" # Red
    elif mode == "warning":
        color = "33" # Yellow
    elif mode == "info2":
        color = "34" # Blue
    elif mode == "output":
        color = "35" # Magenta
    elif mode == "debug":
        color = "37" # White
    else:
        color = "32"
    msg = "[*] %s. %s" % (msg, getTimestamp(includeDate=True))
    #print("\033[1;%sm%s\n%s\033[1;m" % (color, msg, '-'*len(msg))) # Print dashes under the message
    print("\033[1;%sm%s\033[1;m" % (color, msg))
    # Log the message if LOGGING is enabled
    if loggingON() and mode != "info":
        logEvent("%s: %s" % (getTimestamp(includeDate=True), msg))

def prettyPrintError(ex):
    """ Pretty prints an error/exception message """
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    msg = "Error \"%s\" encountered in \"%s\" line %s: %s" % (exc_type, fname, exc_tb.tb_lineno, ex)
    prettyPrint(msg, "error")

