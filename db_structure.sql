/*tables*/
/*packages*/
CREATE TABLE IF NOT EXISTS package (
  package_id INTEGER PRIMARY KEY,
  Name VARCHAR(100) NOT NULL UNIQUE,
  DisplayName VARCHAR(100) NOT NULL,
  Category VARCHAR(250) NOT NULL,
  CommunityDescription TEXT NOT NULL,
  ExternalDependecies VARCHAR(250) NOT NULL,
  OrphanedPackage INTEGER NOT NULL,
  RepositoryFileName VARCHAR(250) NOT NULL,
  RepositoryFileSize INTEGER NOT NULL,
  RepositoryFileHash CHAR(32) NOT NULL,
  RepositoryDate REAL NOT NULL,
  PackageBaseDir VARCHAR(250) NOT NULL,
  HomePageURL VARCHAR(250) NOT NULL,
  DownloadURL VARCHAR(250) NOT NULL,
  SVNURL VARCHAR(250) NOT NULL,
  Rating REAL NOT NULL,
  RatingCount INTEGER NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT 1,
  update_json_hash VARCHAR(32) NOT NULL
);

/*packages files*/
CREATE TABLE IF NOT EXISTS package_file (
  package_id INTEGER NOT NULL,
  Name VARCHAR(100) NOT NULL,
  Description TEXT NOT NULL,
  Author TEXT NOT NULL,
  License TEXT NOT NULL,
  RelativeFilePath VARCHAR(250) NOT NULL,
  VersionAsString VARCHAR(100) NOT NULL,
  LazCompatibility VARCHAR(250) NOT NULL,
  FPCCompatibility VARCHAR(250) NOT NULL,
  SupportedWidgetSet VARCHAR(250) NOT NULL,
  PackageType TINYINT NOT NULL, /*0-designtime and runtime, 1-designtime, 2-runtime*/
  DependenciesAsString VARCHAR(250) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT 1,
  PRIMARY KEY(package_id, Name)
);

/*permmited binary/executable files*/
CREATE TABLE IF NOT EXISTS permmited_file (
  package_id INTEGER NOT NULL,
  file_name VARCHAR(100) NOT NULL,
  PRIMARY KEY(package_id, file_name)
);

/*users*/
CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY,
  uuid VARCHAR(64) NOT NULL UNIQUE,
  Name VARCHAR(100) NOT NULL
);

/*rating history*/
CREATE TABLE IF NOT EXISTS rating_history (
  rating_id INTEGER PRIMARY KEY,
  package_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  ip_hash VARCHAR(32) NOT NULL,
  vote_time REAL NOT NULL,
  Rate TINYINT NOT NULL,
  [Comment] TEXT NOT NULL,
  UNIQUE(package_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_rating_history ON rating_history (package_id ASC);
CREATE TRIGGER IF NOT EXISTS update_rating AFTER INSERT ON rating_history FOR EACH ROW
BEGIN
  UPDATE package SET Rating = (SELECT AVG(rate) FROM rating_history WHERE package_id = NEW.package_id), 
    RatingCount = (SELECT COUNT(1) FROM rating_history WHERE package_id = NEW.package_id)
    WHERE package_id = NEW.package_id;
END;

/*failed admins login history*/
CREATE TABLE IF NOT EXISTS login_history (
  ip_hash VARCHAR(32) NOT NULL PRIMARY KEY,
  login_time INTEGER NOT NULL,
  failed INTEGER NOT NULL
);