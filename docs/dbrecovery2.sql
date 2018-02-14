CREATE TABLE learner( 
    lrnID		TEXT PRIMARY KEY, 
    lrnParams		TEXT
);

CREATE TABLE run( 
    runID       	INTEGER, 
    runDataset  	TEXT,
    runStart  		TEXT,
    runEnd		TEXT,
    runIterations	INTEGER,
    PRIMARY KEY (runID, runDataset)
);

CREATE TABLE datapoint ( 
    dpID        	INTEGER PRIMARY KEY AUTOINCREMENT, 
    dpLearner		TEXT,
    dpIteration		INTEGER,
    dpRun		INTEGER,
    dpTimestamp 	TEXT,
    dpFeature           TEXT,
    dpType          	TEXT,
    dpAccuracy		REAL,
    dpRecall		REAL,
    dpSpecificity	REAL,
    dpPrecision		REAL,
    dpFscore		REAL,
    FOREIGN KEY (dpLearner) REFERENCES parent(learnerID),
    FOREIGN KEY (dpRun) REFERENCES parent(runID)
);

CREATE TABLE testapp (
    taName		TEXT,
    taRun		INTEGER,
    taType		TEXT,
    taLog		TEXT
    PRIMARY KEY (taName, taRun),
    FOREIGN KEY (taRun) REFERENCES parent(runID)
);
