#!/usr/bin/python


class App:
    """ A representation of an Android app containing basic knowledge about the app """
    def __init__(self, appName, appID, appVersionCode, appOfferType, appRating, appPrice, appSize):
        self.appName = appName
        self.appID = appID
        self.appVersionCode = appVersionCode
        self.appOfferType = appOfferType
        self.appRating = appRating
        self.appPrice = appPrice
        self.appSize = appSize


