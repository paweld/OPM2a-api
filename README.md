# OPM2a - api
Simple php API for packages administration for the Online Package Manager (Lazarus).

Solution allows you to manage packages and automatically update packages from related `update.json` files - after adding to cron.

**Features:**
- possibility of automatic cloning from another package repository
- has the ability to register package ratings
- automatic package updates (using cron)
- automatically retrieves information about packages (author, description, version, license, required packages) from `lpk` files, hides the `lpk` file if it does not exist in the new zip file
- automatically deletes files with illegal extensions, but it is possible to add exceptions (specific files)

Available functions in `api.php`:
**Only for administrator:**
- `initdb` (*GET*) - initialization of the package database from the page specified in the configuration - only possible when the database is empty
- `disable` (*GET*) - disable package export to packagelist.json. package name required.
- `forceupdate` (*GET*) - forces download of package updates using related `update.json` file (all packages or just one with given name) and export the whole list. This is available by calling the update.php file, which can eventually be added to the cron so that updates are performed automatically
- ` ` (*POST*) - adding or updating a package from a json file in the same format as `packagelist.json`
- ` ` (*GET*) - get a list of all packages or only one with the given name
- `ratinghistory` (*GET*) - retrieve package rating history

**For all:**
- `rating` (*GET*) - retrieving ratings for packages or one with a given name
- `setrate` (*PUT*) - adding a rating for a given package

Configuration (file paths, forbidden extensions, administrator login data [http basic authorization]) is in the file `opm.php`.

To update or add a new package, please send json in a format like `packagelist.json`. In addition to the standard ones, several additional fields are available:
- `enabled` - show or hide a package or package file. The package file is set automatically on update time
- `package_zip_base64` -base64 encoded package zip file contents
- `PermmitedFiles` - files that cannot be automatically removed from the archive - relative path to the file
example:
```json
{
  "PackageData0" : {
    "Name" : "New Package",
    "DisplayName" : "New Test Package",
    "Category" : "LazIDEPlugins",
    "CommunityDescription" : "New test package.",
    "ExternalDependecies" : "",
    "OrphanedPackage" : 0,
    "RepositoryFileName" : "NewTestPackage.zip",
    "RepositoryFileSize" : 0,
    "RepositoryFileHash" : "",
    "RepositoryDate" : 4.3220304068090278E+004,
    "PackageBaseDir" : "ntpdir\\/",
    "HomePageURL" : "",
    "DownloadURL" : "",
    "SVNURL" : "",
    "package_zip_base64" : "UEsDBBQAAAAAAPOECFEAAAAAAAAAAAAAAAAHAAAAbnRwZGlyL1BLAwQUAAAACAArhQhRVFp8khUCAADJBAAEgAkAAAAAAAAACAgAAAlAAAAbnRwZGlyL250cG1haW4ubHBrCgAgAAAAAAABABgAI1Eq+5Ft1gEjUSr7kW3WAXvZdK2RbdYBUEsBAj8AFAAAAAgAc4UIURbN/R+fAAAA4gAAABIAJAAAAAAAAAAgIAAAagIAAG50cGRpci9udHBtYWluLnBhcwoAIAAAAAAAAQAYAAnrcUySbdYBCetxTJJt1gEtGHatkW3WAVBLBQYAAAAAAwADACEBAAA5AwAAAAA="
  },
  "PackageFiles0" : [
    {
      "Name" : "bad.lpk",
      "Description" : "test ",
      "Author" : "nobody ",
      "License" : "BSD",
      "RelativeFilePath" : "",
      "VersionAsString" : "77.0.0.1",
      "LazCompatibility" : "Trunk",
      "FPCCompatibility" : "Trunk",
      "SupportedWidgetSet" : "win32/win64, gtk2, carbon",
      "PackageType" : 0,
      "DependenciesAsString" : "IDEIntf, FCL"
    }
  ],
  "PermmitedFiles0" : [
  "ntpdir/packages/lazarus/build.cmd",
  "/ntpdir/examples/project1.exe"
  ]
}
```

Repackaging the archive and deleting forbidden files works only for packages updated with `update.json`