#!/usr/bin/python

# Python modules
import sys, os, shutil, glob, io

# Aion modules
from Aion.utils.graphics import *
from Aion.utils.data import *
from Aion.shared.App import App

# Third-party modules
from googleplay_api.googleplay import GooglePlayAPI

class PlayStoreCrawler:

    def __init__(self):
        try:
            creds = loadPlayStoreConfig()
            self.googleLogin = creds['GOOGLE_LOGIN']
            self.googlePassword = creds['GOOGLE_PASSWORD']
            self.androidID = creds['ANDROID_ID']
            self.authToken = creds['AUTH_TOKEN']
            self.api = GooglePlayAPI(self.androidID) # Login to the Play Store
        except Exception as e:
            prettyPrintError(e)
        
    def login(self):
        """ Logs into the Google account using the received Google credentials """
        try:
            self.api.login(self.googleLogin, self.googlePassword, self.authToken)
        except Exception as e:
           prettyPrintError(e)
           return False

        return True 

    def getCategories(self):
        """ Returns a list of app categories available on Google Play Store """
        try:
            cats = self.api.browse()
            categories = [c.dataUrl[c.dataUrl.rfind('=')+1:] for c in cats.category]
        except Exception as e:
            prettyPrintError(e)
            return []

        return categories


    def getSubCategories(self, category):
        """ Returns a list of app sub-categories available on Google Play Store """
        try:
            sub = self.api.list(category)
            subcategories = [s.docid for s in sub.doc]
        except Exception as e:
            prettyPrintError(e)
            return []

        return subcategories          


    def getApps(self, category, subcategory):
        """ Returns a list of "App" objects found under the given (sub)category """
        try:
            apps = self.api.list(category, subcategory)
            if len(apps.doc) < 1:
                prettyPrint("Unable to find any apps under \"%s\" > \"%s\"" % (category, subcategory), "warning")
                return []
            applications = [App(a.title, a.docid, a.details.appDetails.versionCode, a.offer[0].offerType, a.aggregateRating.starRating, a.offer[0].formattedAmount, a.details.appDetails.installationSize) for a in apps.doc[0].child]

        except Exception as e:
            prettyPrintError(e)
            return []

        return applications

    def downloadApp(self, application):
        """ Downloads an app from the Google play store and moves it to the "downloads" directory """
        try:
            if application.appPrice != "Free":
                prettyPrint("Warning, downloading a non free application", "warning")
            # Download the app     
            data = self.api.download(application.appID, application.appVersionCode, application.appOfferType)
            io.open("%s.apk" % application.appID, "wb").write(data)
            downloadedApps = glob.glob("./*.apk")
            dstDir = loadDirs()["DOWNLOADS_DIR"]
            for da in downloadedApps:
                shutil.move(da, dstDir)
            
        except Exception as e:
            prettyPrintError(e)
            return False
 
        return True

