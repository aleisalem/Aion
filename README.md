## Welcome to Aion

Aion is a framework (under construction) meant to apply the notion of active learning to the problem of stimulation, analysis, and detection of Android repackaged/piggybacked malware.

In a nutshell, the framework is developed as a set of tools and utilites categorized according to their objective. For example, [data_inference] contains different machine learning feature extraction, feature selection, and classification modules and methods. Those utilities are used as an API by tools residing under the [tools] directory.

We are still experimenting with the applicability of such an idea, hence the lack of proper documentation.

### Requirements

Aion utilizes various tools including:

- [androguard](https://github.com/androguard/androguard): for static analysis of APK's and retrieval of components and other metadata
- [Genymotion](https://www.genymotion.com/fun-zone/): we rely on Genymotion to run AVD on which apps are tested and monitored.
- [Droidbot](http://honeynet.github.io/droidbot): used as an option for randomly-interacting with an APK-under-test.
- [droidmon](https://github.com/idanr1986/droidmon): keeps track of the app's runtime behavior in the form of API calls it issues.
- [Droidutan](https://github.com/aleisalem/droidutan): a "homemade", less fancy equivalent to Droidbot.
- [scikit-learn](scikit-learn.org): the main provider of machine learning algorithms.
### Support or Contact

Please feel free to pull/fork the repository. We kindly ask you to cite us, if anything useful comes out of your endeavors.

You can get in touch with the contributor of this repository via [salem@in.tum.de].

Happy hunting. :)
