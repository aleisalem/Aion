CREATE TABLE learner( 
    learnerID		INTEGER PRIMARY KEY AUTOINCREMENT, 
    learnerName 	TEXT
);

CREATE TABLE run( 
    runID       	INTEGER PRIMARY KEY, 
    runDataset  	TEXT, 
    runStart  		TEXT,
    runEnd		TEXT,
    runIterations	INTEGER
);

CREATE TABLE app( 
    appID       	INTEGER PRIMARY KEY AUTOINCREMENT, 
    appName    		TEXT, 
    appType 		TEXT,
    appRunID  		INTEGER,
    appRuns		INTEGER,
    FOREIGN KEY (appRunID) REFERENCES parent(runID)
);

CREATE TABLE datapoint ( 
    dpID        	INTEGER PRIMARY KEY AUTOINCREMENT, 
    dpLearner		INTEGER,
    dpIteration		INTEGER,
    dpRun		INTEGER,
    dpTimestamp 	TEXT,
    dpType          	TEXT,
    dpAccuracy		REAL,
    dpRecall		REAL,
    dpSpecificity	REAL,
    dpPrecision		REAL,
    dpFscore		REAL,
    FOREIGN KEY (dpLearner) REFERENCES parent(learnerID),
    FOREIGN KEY (dpRun) REFERENCES parent(runID)
);

INSERT INTO learner (learnerName) VALUES ("KNN10");
INSERT INTO learner (learnerName) VALUES ("KNN25");
INSERT INTO learner (learnerName) VALUES ("KNN50");
INSERT INTO learner (learnerName) VALUES ("KNN100");
INSERT INTO learner (learnerName) VALUES ("KNN250");
INSERT INTO learner (learnerName) VALUES ("KNN500");
INSERT INTO learner (learnerName) VALUES ("Trees10");
INSERT INTO learner (learnerName) VALUES ("Trees25");
INSERT INTO learner (learnerName) VALUES ("Trees50");
INSERT INTO learner (learnerName) VALUES ("Trees75");
INSERT INTO learner (learnerName) VALUES ("Trees100");
INSERT INTO learner (learnerName) VALUES ("SVM");
INSERT INTO learner (learnerName) VALUES ("Ensemble");
