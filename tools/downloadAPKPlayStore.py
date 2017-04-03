#!/usr/bin/python

from Aion.data_generation.collection.playStoreCrawler import PlayStoreCrawler # The crawler
from Aion.utils.graphics import * # Needed for pretty printing

import os, sys, glob, shutil, argparse, subprocess

def defineArguments():
    parser = argparse.ArgumentParser(prog="downloadAPKPlayStore.py", description="Uses \"Aion\"'s Play Store crawler to download APK's of benign applications.")
    parser.add_argument("-m", "--mode", help="Help", required=True, choices=["download-all", "download-category", "download-subcategory", "update"])
    parser.add_argument("-n", "--num", help="The number of APK's to download", required=False, default=10)
    parser.add_argument("-c", "--category", help="The category of the APK's to download", required=False, default="")
    parser.add_argument("-s", "--subcategory", help="The sub-category of the APK's to download", required=False, default="")
    parser.add_argument("-f", "--freeapps", help="Whether to exclusively download free apps", required=False, choices=["yes", "no"], default="no")
    parser.add_argument("-o", "--outdir", help="The directory to save the downloaded APK's", required=False, default=".")
    parser.add_argument("-r", "--repo", help="The file containing the already downloaded APK's", required=False, default="repo.csv")
    parser.add_argument("-v", "--verbose", help="Display debug messages", default="no", choices=["yes", "no"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Welcome to the droid hunter")
 
        # Step 0 - Load the repo of downloaded APK's
        if not os.path.exists(arguments.repo):
            prettyPrint("Could not locate the repository of downloaded APK's. Creating a new one", "warning")
            repoFile = open("repo.csv", "w")
        else:
            repoFile = open(arguments.repo, "a+")
            downloadedApps = repoFile.read().split(",")
            if arguments.verbose == "yes":
                prettyPrint("Successfully retrieved %s apps from the repository \"%s\"" % (len(downloadedApps), arguments.repo), "debug")

        if arguments.mode == "download-all":
            # Step 1 - Retrieve all categories
            crawler = PlayStoreCrawler()
            if arguments.verbose == "yes":
                prettyPrint("Logging into the Play store", "debug")
            # (1.a) Log into the play store
            if not crawler.login():
                prettyPrint("Unable to login to the Google Play store. Check the credentials in the configuration files", "error")
                return False
            # (1.b) Retrieve app categories
            appCategories = crawler.getCategories()

            if arguments.verbose == "yes" and len(appCategories) > 0:
                prettyPrint("Successfully retrieved %s categories from the Play Store" % len(appCategories), "debug")

            # (1.c) Iterate over each category, retrieving its sub-categories, and apps
            downloadQueue = [] # Store the apps to be downloaded
            for category in appCategories:
                prettyPrint("Processing the category \"%s\"" % category)
                subCategories = crawler.getSubCategories(category)
                if arguments.verbose == "yes" and len(subCategories) > 0:
                    prettyPrint("Successfully retrieved %s sub-categories from the Play Store" % len(subCategories), "debug")
                # (1.d) Iterate over each sub-category, retrieving the apps, and downloading them
                for subCategory in subCategories:
                    prettyPrint("Processing the sub-category \"%s\"" % subCategory)
                    apps = crawler.getApps(category, subCategory)
                    if arguments.verbose == "yes" and len(apps) > 0:
                        prettyPrint("Successfully retrieved %s apps from the Play Store" % len(apps), "debug")
                    # (1.e) Add the apps to the downloading queue (if we do NOT already have them)
                    for app in apps:
                        # A check about the app being "free" and whether to download it
                        if app.appPrice.lower() == "free" and arguments.freeapps == "yes":
                            if not app in downloadedApps and not app in downloadQueue:
                                downloadQueue.append(app)
            
            # Calculate the sizes of the to-be-downloaded apps
            totalSize = sum(app.appSize for app in downloadQueue)
            #for app in downloadQueue:
            #    print "%s is of size %s, and costs %s" % (app.appName, sizeof_fmt(app.appSize), app.appPrice)
            # (1.f) Confirm downloading the queued apps
            prettyPrint("Successfully retrieved %s apps to download with total size of %s" % (len(downloadQueue), sizeof_fmt(totalSize)))
            confirmDownload = raw_input("Download apps? [Y/n] ")
            if confirmDownload == "" or confirmDownload.lower() == "y":
                # Step 2 - Download the APK's
                for app in downloadQueue:
                    prettyPrint("Downloading \"%s\"." % app.appID)
                    crawler.downloadApp(app)
		    # Step 3 - Copy the downloaded APK to the output directory
                    for downloadedApp in glob.glob("./*.apk"):
                        # (3.a) Check whether the out directory exists and create it otherwise
                        if arguments.outdir.lower().find(":") != -1:
                            # Consider this to be a remote directory, and use "scp" to copy the app
                            if arguments.verbose == "yes":
                                prettyPrint("Using \"scp\" to copy the APK's to remote site", "debug")
                                scpArgs = ["sshpass", SSH_PASSWORD, "scp", downloadedApp, "%s@" % arguments.outdir]
                                subprocess.Popen(scpArgs, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
                                os.remove(app)
                                # Add app name to repo
                                repoFile.write(app.appID)
                        else:
                            if arguments.verbose == "yes":
                                prettyPrint("Copying %s to local directory %s" % (app.appID, arguments.outdir), "debug")
                            if not os.path.exists(arguments.outdir):
                                os.mkdir(arguments.outdir)
                            # Move the APK's one-by-one, if it does not exist
                            print "%s/%s.apk" % (arguments.outdir, app.appID)
                            if not os.path.exists("%s/%s.apk" % (arguments.outdir, app.appID)):
                                shutil.move(downloadedApp, arguments.outdir)
                                # Add app name to repo
                                repoFile.write("%s," % app.appID)
                                repoFile.flush() # Write app names right away
                            else:
                                prettyPrint("App \"%s\" already exists in the output directory \"%s\". Skipping" % (app.appID, arguments.outdir), "warning")
                                os.remove("./%s.apk" % app.appID)
                         
            else:
                prettyPrint("As you wish")
                return True
            
        repoFile.close()

    except Exception as e:
        prettyPrintError(e)
        return False
    
    prettyPrint("Good day to you ^_^")
    return True

if __name__ == "__main__":
    main() 
