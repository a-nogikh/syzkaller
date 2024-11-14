CREATE TABLE Series (
    ID STRING(36) NOT NULL, -- UUID
    Title STRING(512) NOT NULL,
    Link STRING(512) NOT NULL,
    Cc ARRAY<STRING(256)>,
) PRIMARY KEY (ID);

CREATE TABLE Patches (
    ID STRING(36) NOT NULL, -- UUID
    SeriesID STRING(36) NOT NULL,
    Title STRING(512) NOT NULL,
    Link STRING(512) NOT NULL,
    -- Spanner limits max STRING length, so it's better to store binary data elsewhere, e.g. in GCS.
    BodyURI STRING(512) NOT NULL,
    CONSTRAINT FK_SeriesPatches FOREIGN KEY (SeriesID) REFERENCES Series (ID),
) PRIMARY KEY(ID);

CREATE TABLE Builds (
    ID STRING(36) NOT NULL, -- UUID
    SeriesID STRING(36), -- NULL if no series were applied to the tree.
    Repo STRING(256) NOT NULL,
    CommitHash STRING(256) NOT NULL,
    Status STRING(32) NOT NULL,
    CONSTRAINT StatusEnum CHECK (Status IN ('success', 'failed', 'error', 'in_progress')),
) PRIMARY KEY(ID);

/*
    Why we need the Session entity:

    There could be multiple sessions per a patch series, e.g. if we want to try out several
    possible base trees or want to retry fuzzing after having updated the system.
*/

CREATE TABLE Sessions (
    ID STRING(36) NOT NULL, -- UUID
    SeriesID STRING(36) NOT NULL,
    BaseBuildID STRING(36) NOT NULL,
    PatchedBuildID STRING(36) NOT NULL,
    StartedAt TIMESTAMP NOT NULL,
    FinishedAt TIMESTAMP,
    CONSTRAINT FK_SeriesSessions FOREIGN KEY (SeriesID) REFERENCES Series (ID),
    CONSTRAINT FK_BaseBuild FOREIGN KEY (BaseBuildID) REFERENCES Builds (ID),
    CONSTRAINT FK_PatchedBuild FOREIGN KEY (PatchedBuildID) REFERENCES Builds (ID),
) PRIMARY KEY(ID);

CREATE TABLE SessionTests (
    SessionID STRING(36) NOT NULL, -- UUID
    Name STRING(256) NOT NULL,
    JobKey STRING(256) NOT NULL, -- A K8S job key.
    StartedAt TIMESTAMP,
    FinishedAt TIMESTAMP,
    Result STRING(36) NOT NULL,
    CONSTRAINT FK_SessionResults FOREIGN KEY (SessionID) REFERENCES Sessions (ID),
    CONSTRAINT ResultEnum CHECK (Result IN ('passed', 'failed', 'error', 'in_progress')),
) PRIMARY KEY(SessionID, Name);

CREATE TABLE Crashes (
    ID STRING(36) NOT NULL, -- UUID
    SessionID STRING(36) NOT NULL,
    TestName STRING(256) NOT NULL,
    Title STRING(256) NOT NULL,
    ReportURI STRING(256) NOT NULL,
    ConsoleLogURI STRING(256) NOT NULL,
    CONSTRAINT FK_SessionCrashes FOREIGN KEY (SessionID) REFERENCES Sessions (ID),
    CONSTRAINT FK_TestCrashes FOREIGN KEY (SessionID, TestName) REFERENCES SessionTests (ID, Name),
) PRIMARY KEY(CrashID);
