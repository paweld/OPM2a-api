<?php
/*
--------------------------------------------------------------------------------
|                              MIT License                                     |
|                                                                              |
| Copyright (c) 2020 Paweł Dmitruk, https://github.com/paweld                  |
|                                                                              |
| Permission is hereby granted, free of charge, to any person obtaining        |
| a copy of this software and associated documentation files (the "Software"), |
| to deal in the Software without restriction, including without limitation    |
| the rights to use, copy, modify, merge, publish, distribute, sublicense,     |
| and/or sell copies of the Software, and to permit persons to whom            |
| the Software is furnished to do so, subject to the following conditions:     |
|                                                                              |
| The above copyright notice and this permission notice shall be included      |
| in all copies or substantial portions of the Software.                       |
|                                                                              |
| THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR   |
| IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,     |
| FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL      |
| THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER   |
| LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,              |
| ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE           |
| OR OTHER DEALINGS IN THE SOFTWARE.                                           |
--------------------------------------------------------------------------------
*/

ini_set("allow_url_fopen", 1);

class OPM
{
  /*variables*/
  /*info log file - if emty no info logs*/
  private $cfg_info_log = '../data/info.log';
  /*error log file - if emty no error logs*/
  private $cfg_error_log = '../data/error.log';
  /*sqlite dbfile path*/
  private $cfg_db_file = '../data/opm.db';
  /*dir for packagelist.json and zip files*/
  private $cfg_main_path = '../';
  /*temporary folder*/
  private $cfg_tmp_path = '../tmp/';
  /*excluded extensions*/
  private $cfg_exc_ext = array('exe', 'msi', 'dll', 'so', 'bat', 'cmd', 'sh');
  /*admin list - users with permisions to package editing simple api*/
  /*array name => password*/
  /*http basic authorization*/
  private $cfg_admins = array("opm-admin" => "*6>S}bG4U!TL^s=2");
  /*init repository*/
  private $initrepo = 'https://packages.lazarus-ide.org/';
  //private $initrepo = 'http://localhost/opm_org/';
  
  private $db;
  private $initmode; //if initialize then rating import and download packages zip
  private $tmp_dir;
  private $lpk_xml_arr;
  private $lpk_xml_path;
  private $parser;
  private $updated_pkgs;
  
  /*constructor*/
  public function __construct()
  {
    $this->initmode = false;
    $this->createPath($this->cfg_main_path);
    $this->createPath(dirname($this->cfg_db_file));
    if ($this->cfg_info_log != '')
      $this->createPath(dirname($this->cfg_info_log));
    if ($this->cfg_error_log != '')
      $this->createPath(dirname($this->cfg_error_log));
    $result = $this->checkDB();
    if ($result != '')
      throw new Exception($result);
    $this->tmp_dir = '';
  }
  
  /*destructor*/
  public function __destruct()
  {
    if (($this->tmp_dir != '') && ($this->tmp_dir != $this->cfg_main_path) && ($this->tmp_dir != $this->cfg_tmp_path) && ($this->tmp_dir != '/tmp/'))
      $this->deleteDir($this->tmp_dir);
  }
  
  /*save log to file*/
  public function addLog($is_error, $log_msg)
  {  
    if (($is_error) && ($this->cfg_error_log != ''))
    {
      file_put_contents($this->cfg_error_log, date('Y-m-d H:i:s') . ': ' . $log_msg . "\n", FILE_APPEND | LOCK_EX);
    }
    elseif ((!$is_error) && ($this->cfg_info_log != ''))
    {
      file_put_contents($this->cfg_info_log, date('Y-m-d H:i:s') . ': ' . $log_msg . "\n", FILE_APPEND | LOCK_EX);
    }
  }
  
  /*create database if empty*/
  private function checkDB()
  {
    $result = '';
    $db_exists = (file_exists($this->cfg_db_file));
    try
    {
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      if (!$db_exists)
      {
        /*create tables*/
        $sql = " CREATE TABLE IF NOT EXISTS package ( ";
        $sql .= "   package_id INTEGER PRIMARY KEY, ";
        $sql .= "   Name VARCHAR(100) NOT NULL UNIQUE, ";
        $sql .= "   DisplayName VARCHAR(100) NOT NULL, ";
        $sql .= "   Category VARCHAR(250) NOT NULL, ";
        $sql .= "   CommunityDescription TEXT NOT NULL, ";
        $sql .= "   ExternalDependecies VARCHAR(250) NOT NULL, ";
        $sql .= "   OrphanedPackage INTEGER NOT NULL, ";
        $sql .= "   RepositoryFileName VARCHAR(250) NOT NULL, ";
        $sql .= "   RepositoryFileSize INTEGER NOT NULL, ";
        $sql .= "   RepositoryFileHash CHAR(32) NOT NULL, ";
        $sql .= "   RepositoryDate REAL NOT NULL, ";
        $sql .= "   PackageBaseDir VARCHAR(250) NOT NULL, ";
        $sql .= "   HomePageURL VARCHAR(250) NOT NULL, ";
        $sql .= "   DownloadURL VARCHAR(250) NOT NULL, ";
        $sql .= "   SVNURL VARCHAR(250) NOT NULL, ";
        $sql .= "   Rating REAL NOT NULL, ";
        $sql .= "   RatingCount INTEGER NOT NULL, ";
        $sql .= "   enabled BOOLEAN NOT NULL DEFAULT 1, ";
        $sql .= "   update_json_hash VARCHAR(32) NOT NULL ";
        $sql .= " ); ";
        $this->db->exec($sql);
        $sql = " CREATE TABLE IF NOT EXISTS package_file ( ";
        $sql .= "   package_id INTEGER NOT NULL, ";
        $sql .= "   Name VARCHAR(100) NOT NULL, ";
        $sql .= "   Description TEXT NOT NULL, ";
        $sql .= "   Author TEXT NOT NULL, ";
        $sql .= "   License TEXT NOT NULL, ";
        $sql .= "   RelativeFilePath VARCHAR(250) NOT NULL, ";
        $sql .= "   VersionAsString VARCHAR(100) NOT NULL, ";
        $sql .= "   LazCompatibility VARCHAR(250) NOT NULL, ";
        $sql .= "   FPCCompatibility VARCHAR(250) NOT NULL, ";
        $sql .= "   SupportedWidgetSet VARCHAR(250) NOT NULL, ";
        $sql .= "   PackageType TINYINT NOT NULL, ";
        $sql .= "   DependenciesAsString VARCHAR(250) NOT NULL, ";
        $sql .= "   enabled BOOLEAN NOT NULL DEFAULT 1, ";
        $sql .= "   PRIMARY KEY(package_id, Name) ";
        $sql .= " ); ";
        $this->db->exec($sql);
        $sql = " CREATE TABLE IF NOT EXISTS permmited_file ( ";
        $sql .= "   package_id INTEGER NOT NULL, ";
        $sql .= "   file_name VARCHAR(100) NOT NULL, ";
        $sql .= "   PRIMARY KEY(package_id, file_name) ";
        $sql .= " ); ";
        $this->db->exec($sql);
        $sql = " CREATE TABLE IF NOT EXISTS users ( ";
        $sql .= "   user_id INTEGER PRIMARY KEY, ";
        $sql .= "   uuid VARCHAR(64) NOT NULL UNIQUE, ";
        $sql .= "   Name VARCHAR(100) NOT NULL ";
        $sql .= " ); ";
        $this->db->exec($sql);
        $sql = " CREATE TABLE IF NOT EXISTS rating_history ( ";
        $sql .= "  rating_id INTEGER PRIMARY KEY, ";
        $sql .= "  package_id INTEGER NOT NULL, ";
        $sql .= "  user_id INTEGER NOT NULL, ";
        $sql .= "  ip_hash VARCHAR(32) NOT NULL, ";
        $sql .= "  vote_time REAL NOT NULL,";
        $sql .= "  Rate TINYINT NOT NULL, ";
        $sql .= "  [Comment] TINYINT NOT NULL, ";
        $sql .= "  UNIQUE(package_id, user_id) ";
        $sql .= "); ";
        $this->db->exec($sql);
        $sql = " CREATE INDEX IF NOT EXISTS idx_rating_history ON rating_history (package_id ASC); ";
        $this->db->exec($sql);
        $sql = " CREATE TRIGGER IF NOT EXISTS update_rating AFTER INSERT ON rating_history FOR EACH ROW ";
        $sql .= " BEGIN ";
        $sql .= "   UPDATE package SET Rating = (SELECT AVG(rate) FROM rating_history WHERE package_id = NEW.package_id), ";
        $sql .= "     RatingCount = (SELECT COUNT(1) FROM rating_history WHERE package_id = NEW.package_id) ";
        $sql .= "     WHERE package_id = NEW.package_id; ";
        $sql .= " END; ";
        $this->db->exec($sql);
        $sql = " CREATE TABLE IF NOT EXISTS login_history ( ";
        $sql .= "   ip_hash VARCHAR(32) NOT NULL PRIMARY KEY, ";
        $sql .= "   login_time INTEGER NOT NULL, ";
        $sql .= "   failed INTEGER NOT NULL ";
        $sql .= " ); ";
        $this->db->exec($sql);
      }
      $this->db = null;
    }
    catch (Exception $e)
    {
      $this->addLog(true, 'Database connect error');
      $result = json_encode(array('status' => 'error', 'message' => 'Database connect error'), JSON_PRETTY_PRINT);
    }
    
    return $result;
  }
  
  /*is string contains string*/
  private function isBegins($s, $pattern)
  {
    $result = (strlen($s) > strlen($pattern));
    if ($result)
      $result = (substr($s, 0, strlen($pattern)) == $pattern);
    
    return $result;
  }
  
  /*is directory empty*/
  private function isDirEmpty($dir) 
  {
    $result = is_dir($dir);
    if ($result)
      $result = (count(scandir($dir)) == 2);
    
    return $result;
  }
  
  /*convert datetime to float*/
  private function datetimeToFloat($datetime)
  {
    $dt0 = new DateTime('1900-01-01 00:00:00');
    $dt1 = new DateTime($datetime); 
    $interval = $dt0->diff($dt1);
    $d = 2 + $interval->format('%a');
    $t = (($interval->format('%h') * 60 * 60) + ($interval->format('%i') * 60) + $interval->format('%s')) / (24 * 60 * 60);
    
    return $d + $t;
  }
  
  /*create path*/
  private function createPath($path) 
  {
    if (is_dir($path)) 
    {
      return true;
    }
    else
    {
      $prev_path = substr($path, 0, strrpos($path, '/', -2) + 1);
      $result = $this->createPath($prev_path);
      return ($result && is_writable($prev_path)) ? mkdir($path) : false;
    }
  }
    
  /*generate tmp dir path*/
  private function createTempDir() 
  {
    if ($this->tmp_dir == '')
    {
      $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $characters_len = strlen($characters);
      if ($this->createPath($this->cfg_tmp_path))
      {
        $dir = $this->cfg_tmp_path;
      }
      else
      {
        $dir = $this->cfg_main_path;
      }
      for ($i = 0; $i < 16; $i++) 
      {
          $dir .= $characters[rand(0, $characters_len - 1)];
      }
      if (!$this->createPath($dir))
        $dir = '/tmp';
      $this->tmp_dir = realpath($dir) . '/';
    }
  }
  
  /*get packagelist.json file name*/
  public function getJsonFileName()
  {
    return $this->cfg_main_path . '/packagelist.json';
  }
  
  /*get all files in dir and subdirs*/
  /*types: f-files, d-dirs, else all*/
  private function getDirContents($dir, $type = 'f', &$results = array()) 
  {
    if (file_exists($dir))
    {
      $files = scandir($dir);
      foreach ($files as $value) 
      {
        $path = realpath($dir . '/' . $value);
        if (!is_dir($path))
        {
          if ($type != 'd')
            $results[] = $path;
        } 
        elseif (($value != ".") && ($value != "..")) 
        {
          $this->getDirContents($path, $type, $results);
          if ($type != 'f')
            $results[] = $path;
        }
      }
    }
    
    return $results;
  }
  
  /*get client ip*/
  private function getClientIP()
  {
    /*behind CloudFlare network*/
    if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) 
    {
      $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
      $_SERVER['HTTP_CLIENT_IP'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
    }
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
      $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
      $ip = $forward;
    }
    else
    {
      $ip = $remote;
    }
    
    return $ip;
  }
  
  /*delete directory with files*/
  private function deleteDir($dir)
  {
    $result = false;
    $files_arr = $this->getDirContents($dir, 'f');
    foreach($files_arr as $file)
    {
      if (file_exists($file))
        unlink($file);
    }
    $dir_arr = $this->getDirContents($dir, 'd');
    foreach ($dir_arr as $subdir)
    {
      if ((file_exists($subdir)) && ($this->isDirEmpty($subdir)))
        rmdir($subdir);
    }
    if ($this->isDirEmpty($dir)) 
      $result = rmdir($dir);
    
    return $result;
  }
  
  /*get empty string if array key not exist*/
  private function getArrayStrVal($key, $array, $default = '', $default_is_emty = false)
  {
    $result = (array_key_exists($key, $array) ? $array[$key] : $default);
    if (($result == '') && ($default_is_emty) && ($result != $default))
      $result = $default;
    
    return $result;
  }
  
  /*get info from lpk file*/ 
  private function getLpkInfoFormFile($file_name)
  {
    $xml = file_get_contents($file_name);
    
    return $this->getLpkInfo($xml);
  }
  
  /*get info from lpk body*/
  private function startElements($parser, $name, $attrs) 
  {    
    if (!empty($name)) 
    {
      $this->xml_path .= '/' . $name;
      
      if ($this->isBegins($this->xml_path, '/CONFIG/PACKAGE/REQUIREDPKGS'))
      {
        if ($name == 'PACKAGENAME')
        {
          $this->lpk_xml_arr['dependecies'] .= (($this->lpk_xml_arr['dependecies'] == '') ? '' : ', ') . $attrs['VALUE'];
        }
        elseif ($name == 'MINVERSION')
        {
          $this->lpk_xml_arr['dependecies'] .= ' (' . $this->getArrayStrVal('MAJOR', $attrs, '0') . '.' . $this->getArrayStrVal('MINOR', $attrs, '0') . '.' . $this->getArrayStrVal('REVISION', $attrs, '0') . '.' . $this->getArrayStrVal('BUILD', $attrs, '0') . ')';
        }
      }
      else
      {
        switch ($this->xml_path) 
        {
          case '/CONFIG/PACKAGE/TYPE':
            if ($attrs['VALUE'] == 'RunAndDesignTime')
            {
              $this->lpk_xml_arr['type'] = 0;
            }
            elseif ($attrs['VALUE'] == 'DesignTime')
            {
                $this->lpk_xml_arr['type'] = 1;
            }
            else
              $this->lpk_xml_arr['type'] = 2;
            break;
          case '/CONFIG/PACKAGE/AUTHOR':
            $this->lpk_xml_arr['author'] = $attrs['VALUE'];
            break;
          case '/CONFIG/PACKAGE/DESCRIPTION':
            $this->lpk_xml_arr['desc'] = $attrs['VALUE'];
            break;
           case '/CONFIG/PACKAGE/LICENSE':
            $this->lpk_xml_arr['license'] = $attrs['VALUE'];
            break;
          case '/CONFIG/PACKAGE/VERSION':
            $this->lpk_xml_arr['version'] = $this->getArrayStrVal('MAJOR', $attrs, '0') . '.' . $this->getArrayStrVal('MINOR', $attrs, '0') . '.' . $this->getArrayStrVal('REVISION', $attrs, '0') . '.' . $this->getArrayStrVal('BUILD', $attrs, '0');
            break;
        }
      }
    }
  }
  
  private function endElements($parser, $name) 
  {
    if (!empty($name))
      $this->xml_path = substr($this->xml_path, 0, strlen($this->xml_path) - strlen('/' . $name));
  }
  
  public function getLpkInfo($xml)
  {
    $this->lpk_xml_arr = array('type' => 2, 'author' => '', 'desc' => '', 'license' => '', 'version' => '0.0.0.0', 'dependecies' => '');
    $this->xml_path = '';
    
    /*parse lpk*/
    $this->parser = xml_parser_create(); 
    xml_set_object($this->parser, $this);
    xml_set_element_handler($this->parser, "startElements", "endElements");  
    xml_parse($this->parser, $xml);
    xml_parser_free($this->parser);
    
    return $this->lpk_xml_arr;
  }
  
  /*get rating*/
  public function getRating($package_name)
  {
    $result = '';
    if ($package_name != '')
    {
      $sql = " SELECT COUNT(1) cnt FROM package WHERE Name = ? ";
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $check_query = $this->db->prepare($sql);
      $check_query->execute([$package_name]);
      if ($check_query->fetch(PDO::FETCH_ASSOC)['cnt'] == 0)
        $result = json_encode(array('status' => 'error', 'message' => 'Incorrect data'), JSON_PRETTY_PRINT);
      $this->db - null;
    }
    if ($result == '')
    {
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $sql = " SELECT Name, Rating, RatingCount FROM package ";
      if ($package_name != '')
        $sql .= " WHERE Name = " . $this->db->quote($package_name);
      $sql .= " ORDER BY lower(Name) ASC ";
      $getrating_query = $this->db->query($sql);
      $rating_arr = array();
      while ($getrating_row = $getrating_query->fetch(PDO::FETCH_ASSOC))
      {
        $rating_arr[$getrating_row['Name']] = array("Rating" => $getrating_row['Rating'], "RatingCount" => $getrating_row['RatingCount']);
      }
      $getrating_query = null;
      $result = json_encode($rating_arr, JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);
    }
    
    return $result;
  }
  
  /*set rating*/
  public function setRating($package_name, $uuid, $rate, $json)
  {
    $result = '';
    $package_id = 0;
    $user_id = 0;
    $uuid_tmp = $uuid;
    if (($package_name == '') || (!is_numeric($rate)) || ($rate < 0) || ($rate > 5))
    {
      $result = json_encode(array('status' => 'error', 'message' => 'Incorrect data'), JSON_PRETTY_PRINT);
    }
    else 
    {
      if ($uuid_tmp != '')
      {
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = " SELECT COUNT(1) cnt, IFNULL(MAX(user_id), 0) uid FROM users WHERE uuid = ? ";
        $checkuser_query = $this->db->prepare($sql);
        $checkuser_query->execute([$uuid_tmp]);
        $user_id = $checkuser_query->fetch(PDO::FETCH_ASSOC)['uid'];
        $checkuser_query = null;
        if ($user_id == 0)
          $result = json_encode(array('status' => 'error', 'message' => 'Invalid user identificator'), JSON_PRETTY_PRINT);
      }
      if ($result == '')
      {
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = " SELECT COUNT(1) cnt, IFNULL(MAX(package_id), 0) pid FROM package WHERE Name = ? ";
        $check_query = $this->db->prepare($sql);
        $check_query->execute([$package_name]);
        $package_id = $check_query->fetch(PDO::FETCH_ASSOC)['pid'];
        $check_query = null;
        $comment_arr = array();
        if ($json != '')
          $comment_arr = json_decode($json, true);
        if ($package_id > 0)
        {
          $ip = md5($this->getClientIP());
          $user_name = $this->getArrayStrVal('Author', $comment_arr, '[Anonymous]', true);
          $comment = $this->getArrayStrVal('Comment', $comment_arr); 
          if ($user_id == 0)
          {
            $sql = " INSERT INTO users (uuid, Name) ";
            $sql .= " VALUES (:uuid, :name) ";
            $uuid_tmp = date('Y-m-d H:i:s') . $ip;
            for ($i = 0; $i < 16; $i++)
            {
              $uuid_tmp .= chr(rand(32, 126));
            }
            $uuid_tmp = hash('sha256', $uuid_tmp);
            $this->db = new PDO('sqlite:' . $this->cfg_db_file);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $adduser_query = $this->db->prepare($sql);
            $adduser_query->bindParam(':uuid', $uuid_tmp, PDO::PARAM_STR);
            $adduser_query->bindParam(':name', $user_name, PDO::PARAM_STR);
            $adduser_query->execute();
            $sql = " SELECT user_id FROM users WHERE uuid = ? ";
            $getuser_query = $this->db->prepare($sql);
            $getuser_query->execute([$uuid_tmp]);
            $user_id = $getuser_query->fetch(PDO::FETCH_ASSOC)['user_id'];
            $getuser_query = null;
          }
          else
          {
            $sql = " UPDATE users SET Name = :name WHERE user_id = :user_id ";
            $this->db = new PDO('sqlite:' . $this->cfg_db_file);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $updateuser_query = $this->db->prepare($sql);
            $updateuser_query->bindParam(':user_id', $user_id, PDO::PARAM_INT);
            $updateuser_query->bindParam(':name', $user_name, PDO::PARAM_STR);
            $updateuser_query->execute();
            $updateuser_query = null;
          }
          $sql = " INSERT OR REPLACE INTO rating_history (package_id, user_id, ip_hash, vote_time, rate, [comment]) ";
          $sql .= " VALUES (:package_id, :user_id, :ip, :date, :rate, :comm) ";
          $this->db = new PDO('sqlite:' . $this->cfg_db_file);
          $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
          $rating_query = $this->db->prepare($sql);
          $rating_query->bindParam(':package_id', $package_id, PDO::PARAM_INT);
          $rating_query->bindParam(':user_id', $user_id, PDO::PARAM_INT);
          $rating_query->bindParam(':ip', $ip, PDO::PARAM_STR);
          $param_date = $this->datetimeToFloat(date('Y-m-d H:i:s'));
          $rating_query->bindParam(':date', $param_date, PDO::PARAM_STR);
          $rating_query->bindParam(':rate', $rate, PDO::PARAM_INT);
          $rating_query->bindParam(':comm', $comment, PDO::PARAM_STR);
          $rating_query->execute();
          $sql = " SELECT Rating, RatingCount FROM package WHERE package_id = ? ";
          $checkrating_query = $this->db->prepare($sql);
          $checkrating_query->execute([$package_id]);
          $rating_arr = $checkrating_query->fetchAll(PDO::FETCH_ASSOC);
          $checkrating_query = null;
          $rating_arr = array('Your-UUID' => $uuid_tmp) + $rating_arr;
          $result = json_encode($rating_arr, JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);
        }
        else
        {
          $result = json_encode(array('status' => 'error', 'message' => 'Incorrect data'), JSON_PRETTY_PRINT);
        }
      }
    }
    
    return $result;
  }
  
  /*det comments*/
  public function getComments($package_name)
  {
    $result = '';
    $package_id = 0;
    if ($package_name == '')
    {
      $result = json_encode(array('status' => 'error', 'message' => 'Incorrect data'), JSON_PRETTY_PRINT);
    }
    else 
    {
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $sql = " SELECT COUNT(1) cnt, IFNULL(MAX(package_id), 0) pid FROM package WHERE Name = ? ";
      $check_query = $this->db->prepare($sql);
      $check_query->execute([$package_name]);
      $package_id = $check_query->fetch(PDO::FETCH_ASSOC)['pid'];
      $check_query = null;
      if ($package_id > 0)
      {
        $sql = " SELECT rh.vote_time [Time], u.Name Author, rh.[Comment] FROM rating_history rh INNER JOIN users u ON (rh.user_id = u.user_id) ";
        $sql .= " WHERE rh.package_id = ?  AND rh.[comment] <> '' ORDER BY rh.vote_time ASC ";
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $comments_query = $this->db->prepare($sql);
        $comments_query->execute([$package_id]);
        $comments_arr = $comments_query->fetchAll(PDO::FETCH_ASSOC);
        $comments_query = null;
        $result = json_encode(array($package_name => $comments_arr), JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);
      }
      else
      {
        $result = json_encode(array('status' => 'error', 'message' => 'Incorrect data'), JSON_PRETTY_PRINT);
      }
    }
    
    return $result;
  }
  
  /*check autehentication*/
  public function checkAuth($login, $password)
  {
    $result = '';
    $cnt = 0;
    $lastdt = 0;
    $ip = md5($this->getClientIP());
    $sql = " SELECT failed, login_time FROM login_history WHERE ip_hash = ? ";
    $this->db = new PDO('sqlite:' . $this->cfg_db_file);
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $check_query = $this->db->prepare($sql);
    try
    {
      $check_query->execute([$ip]);
      $check_row = $check_query->fetch(PDO::FETCH_ASSOC);
      $cnt = $check_row['failed'] + 1;
      $lastdt = $check_row['login_time'];
    }
    catch (Exception $e) { }
    finally
    {
      $check_query = null;
    }
    if ($cnt >= 20)
    {
      if (($lastdt + (24 * 60 * 60)) >= time())
        $result = 'You have exceeded the number of login attempts. Please try again in 24 hours';
    }
    elseif ($cnt >= 10)
    {
      if (($lastdt + (60 * 60)) >= time())
        $result = 'You have exceeded the number of login attempts. Please try again in 1 hour';
    }
    elseif ($cnt >= 5)
    {
      if (($lastdt + (15 * 60)) >= time())
        $result = 'You have exceeded the number of login attempts. Please try again in 15 minutes';
    }
    if ($result == '')
    {
      if (array_key_exists($login, $this->cfg_admins))
      {
        if (!$this->cfg_admins[$login] === $password)
          $result = 'Incorrect login or password';
      }
      else
      {
        $result = 'Incorrect login or password';
      }
    }    
    $sql = " INSERT OR REPLACE INTO login_history (ip_hash, login_time, failed) ";
    $sql .= " SELECT :ip, STRFTIME('%s','now'), ";
    if ($result == '')
    {
      $sql .= " 0 ";
    }
    else
    {
      $sql .= " IFNULL((SELECT failed FROM login_history WHERE ip_hash = :ip), 0) + 1 ";
    }
    $this->db = new PDO('sqlite:' . $this->cfg_db_file);
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $login_query = $this->db->prepare($sql);
    $login_query->bindParam(':ip', $ip, PDO::PARAM_STR);
    $login_query->execute();
    $login_query = null;
    if ($result != '')
      $result = json_encode(array('status' => 'error', 'message' => $result), JSON_PRETTY_PRINT);
    
    return $result;
  }
  
  /*get rating history*/
  public function getRatingHistory($package_name)
  {
    $result = json_encode(array('status' => 'error', 'message' => 'No result'), JSON_PRETTY_PRINT);
    $history_arr = array();
    $dbs = true;
    $this->db = new PDO('sqlite:' . $this->cfg_db_file);
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $sql = " SELECT p.package_id, p.Name FROM package p WHERE p.RatingCount > 0 ";
    if ($package_name != '')
      $sql .= " AND p.Name = " . $this->db->quote($package_name);
    $sql .= " ORDER BY lower(p.name) ASC ";
    try 
    {
      $pkg_query = $this->db->query($sql);
      $pkg_arr = $pkg_query->fetchAll(PDO::FETCH_ASSOC);
      $pkg_query = null;
      $dbs = false;
      foreach ($pkg_arr as $pkg_row)
      {
        $sql = " SELECT rh.ip_hash IPHash, rh.vote_time Time, rh.rate Rate, u.Name Author, rh.[Comment] ";
        $sql .= " FROM rating_history rh INNER JOIN users u ON (rh.user_id = u.user_id) WHERE rh.package_id = ? ";
        $sql .= " ORDER BY rh.vote_time ASC, rh.ip_hash ASC, rh.rate ASC ";
        $dbs = true;
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $rh_query = $this->db->prepare($sql);
        try
        {
          $rh_query->execute([$pkg_row['package_id']]);
          $rh_arr = $rh_query->fetchAll(PDO::FETCH_ASSOC);
          $rh_query = null;
          $dbs = false;
          $history_arr[$pkg_row['Name']] = $rh_arr;
        }
        catch (Exception $e) { }
      }
    }
    catch (Exception $e) { }
    if ($dbs)
      $this->db = null;
    if (count($history_arr) > 0)
      $result = json_encode($history_arr, JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);
    
    return $result;
  }
  
  /*disable package*/
  public function disablePackage($package_name)
  {
    $result = '';
    if ($package_name == '')
    {
      $result = json_encode(array('status' => 'error', 'message' => 'You must provide a package name'), JSON_PRETTY_PRINT);
    }
    else 
    {
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $sql = " SELECT COUNT(1) cnt FROM package WHERE Name = ? ";
      $check_query = $this->db->prepare($sql);
      $check_query->execute([$package_name]);
      if ($check_query->fetch(PDO::FETCH_ASSOC)['cnt'] > 0)
      {
        $check_query = null;
        $sql = " UPDATE package SET enabled = 'N' WHERE Name = ? ";
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $disable_query = $this->db->prepare($sql);
        $disable_query->execute([$package_name]);
        $disable_query = null;
        $result = json_encode(array('status' => 'ok', 'message' => 'Package was disabled'), JSON_PRETTY_PRINT);
      }
      else
      {
        $check_query = null;
        $result = json_encode(array('status' => 'error', 'message' => 'You must provide a package correct name'), JSON_PRETTY_PRINT);
      }
    }
    
    return $result;
  }
  
  /*update package files from package.zip and recreate zip package*/
  private function updatePkgFileFromZip($zip_file, $package_id, $package_file_name, $package_file_date, $update_json_hash)
  {
    $this->createTempDir();
    $unzip = new ZipArchive();
    if ($unzip->open($zip_file)) 
    {
      $unzipped_dir = $this->tmp_dir . 'pkg_' . $package_id . '/';
      $unzip->extractTo($unzipped_dir);
      $unzip->close();
      if (file_exists($zip_file))
        unlink($zip_file);
      
      /*disable all package files*/
      $sql = " UPDATE package_file SET enabled = 'N' WHERE package_id = ? ";
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $disablefile_query = $this->db->prepare($sql);
      $disablefile_query->execute([$package_id]);
      $disablefile_query = null;
      
      /*get permmited files*/
      $permfiles_arr = array();
      $sql = " SELECT pf.file_name FROM permmited_file pf WHERE pf.package_id = ? ORDER BY lower(pf.file_name) ASC ";
      $this->db = new PDO('sqlite:' . $this->cfg_db_file);
      $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $permfile_query = $this->db->prepare($sql);
      try
      {
        $permfile_query->execute([$package_id]);
        while ($permfile_row = $permfile_query->fetch(PDO::FETCH_ASSOC))
        {
          $permfiles_arr[] = ($this->isBegins($permfile_row['file_name'], '/')) ? substr($permfile_row['file_name'], 1, strlen($permfile_row['file_name']) - 1) : $permfile_row['file_name'];
        }
      }
      finally
      {
        $permfile_query = null;
      }
      
      if ($package_file_date == 0)
        $package_file_date = $this->datetimeToFloat(date('Y-m-d H:i:s'));
      
      $this->addLog(false, $package_file_name . ": clear excluded files, get lpk's list and zip package");
      $zip = new ZipArchive();
      if ($zip->open($this->tmp_dir . $package_file_name, ZipArchive::CREATE | ZipArchive::OVERWRITE))
      {
        $deleted_files_arr = array();
        $files_arr = $this->getDirContents($unzipped_dir);
        foreach($files_arr as $key => $file)
        {
          $path_info = pathinfo(str_replace($unzipped_dir, '', $file));
          
          /*delete excluded files*/
          $ext = $this->getArrayStrVal('extension', $path_info);
          if ((in_array($ext, $this->cfg_exc_ext)) && (!in_array(str_replace($unzipped_dir, '', $file), $permfiles_arr)))
          {
            if (file_exists($file))
              unlink($file);
            unset($files_arr[$key]);
            $deleted_files_arr[] = $file;
          }
          else
          {
            if ($ext == 'lpk')
            {
              /*get lpk info from db*/
              $sql = " SELECT pf.* from package_file pf WHERE pf.package_id = :packa AND Name = :name ";
              $this->db = new PDO('sqlite:' . $this->cfg_db_file);
              $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
              $pkgfile_query = $this->db->prepare($sql);
              $pkgfile_query->bindParam(':package_name', $package_id, PDO::PARAM_INT);
              $pkgfile_query->bindParam(':name', $path_info['basename'], PDO::PARAM_STR);
              try
              {
                $pkgfile_query->execute();
                $pkgfile_row = $pkgfile_query->fetch(PDO::FETCH_ASSOC);
                $pfdesc = $pkgfile_row['Description'];
                $pfauthor = $pkgfile_row['Author'];
                $pflicense = $pkgfile_row['License'];
                $pfversion = $pkgfile_row['VersionAsString'];
                $pftype = $pkgfile_row['PackageType'];
                $pfdependecies = $pkgfile_row['DependenciesAsString'];
              }
              catch (Exception $e)
              {
                $pfauthor = '';
                $pfversion = '';
                $pfdesc = '';
                $pflicense = '';
                $pfdependecies = '';
                $pftype = '';
              }
              finally
              {
                $pkgfile_query = null;
              }
              /*get lpk info from file*/
              $lpkinfo_arr = $this->getLpkInfoFormFile($file);
              /*... and inset/update into db with enabled only active files */
              $sql = " INSERT OR REPLACE INTO package_file (package_id, Name, Description, Author, License, RelativeFilePath, VersionAsString, ";
              $sql .= " LazCompatibility, FPCCompatibility, SupportedWidgetSet, PackageType, DependenciesAsString, enabled) ";
              $sql .= " SELECT :package_id, :name, :desc, :author, :license, :relpath, :version, ";
              $sql .= " IFNULL((SELECT LazCompatibility FROM package_file WHERE package_id = :package_id AND Name = :name), ''), ";
              $sql .= " IFNULL((SELECT FPCCompatibility FROM package_file WHERE package_id = :package_id AND Name = :name), ''), ";
              $sql .= " IFNULL((SELECT SupportedWidgetSet FROM package_file WHERE package_id = :package_id AND Name = :name), ''), ";
              $sql .= " :type, :dependecies, 'Y' ";
              $param_desc = $this->getArrayStrVal('desc', $lpkinfo_arr, $pfdesc, true);
              $param_author = $this->getArrayStrVal('author', $lpkinfo_arr, $pfauthor, true);
              $param_license = $this->getArrayStrVal('license', $lpkinfo_arr, $pflicense, true);
              $param_relpath = (($path_info['dirname'] == '.') || ($path_info['dirname'] == '..')) ? '' : $path_info['dirname'] . '/';
              $param_version = $this->getArrayStrVal('version', $lpkinfo_arr, $pfversion, true);
              $param_type = $this->getArrayStrVal('type', $lpkinfo_arr, $pftype, true);
              $param_dependecies = $this->getArrayStrVal('dependecies', $lpkinfo_arr, $pfdependecies, true);
              $this->db = new PDO('sqlite:' . $this->cfg_db_file);
              $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
              $updatefile_query = $this->db->prepare($sql);
              $updatefile_query->bindParam(':package_id', $package_id, PDO::PARAM_INT);
              $updatefile_query->bindParam(':name', $path_info['basename'], PDO::PARAM_STR);
              $updatefile_query->bindParam(':desc', $param_desc, PDO::PARAM_STR);
              $updatefile_query->bindParam(':author', $param_author, PDO::PARAM_STR);
              $updatefile_query->bindParam(':license', $param_license, PDO::PARAM_STR);
              $updatefile_query->bindParam(':relpath', $param_relpath, PDO::PARAM_STR);
              $updatefile_query->bindParam(':version', $param_version, PDO::PARAM_STR);
              $updatefile_query->bindParam(':type', $param_type, PDO::PARAM_INT);
              $updatefile_query->bindParam(':dependecies', $param_dependecies, PDO::PARAM_STR);
              $updatefile_query->execute();
              $updatefile_query = null;
            }
            $zip->addFile($file, str_replace($unzipped_dir, '', $file));
          }
        }
        if (count($deleted_files_arr) > 0)
        {
          $dfi_path = '';
          $text = 'Some files have been removed from the archive because they were on the list of forbidden extensions. ' . "\n";
          $text .= 'List of deleted files:' . "\n";
          foreach($deleted_files_arr as $value)
          {
            $text .= $value . "\n";
            if ($dfi_path == '')
              $dfi_path = dirname(str_replace($unzipped_dir, '', $value));
          }
          $text .= 'If you have any comments please contact the OPM maintainer on the Lazarus forum: ' . "\n";
          $text .= 'https://forum.lazarus.freepascal.org/index.php/topic,34297.0.html';
          if (($dfi_path == '') || ($dfi_path == '/'))
          {
            $dfi_path = $unzipped_dir . 'OPM - read_this.txt';
          }
          else
          {
            $dfi_path = $unzipped_dir . explode('/', $dfi_path)[0] . '/OPM - read_this.txt';
          }
          file_put_contents($dfi_path, $text);
          $zip->addFile($dfi_path, str_replace($unzipped_dir, '', $dfi_path));
        }
        $zip->close();
        
        $this->addLog(false, $package_file_name . ' move package zip and clen temp files');
        /*move package zip file to destination*/
        rename($this->tmp_dir . $package_file_name, $this->cfg_main_path . $package_file_name);
        /*update json hash*/
        $sql = " UPDATE package SET RepositoryFileSize = :filesize, RepositoryFileHash = :filehash, ";
        $sql .= " RepositoryDate = :date, update_json_hash = :hash WHERE package_id = :package_id ";
        $param_filesize = filesize($this->cfg_main_path . $package_file_name);
        $param_filehash = md5_file($this->cfg_main_path . $package_file_name);
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $updatepkg_query = $this->db->prepare($sql);
        $updatepkg_query->bindParam(':filesize', $param_filesize, PDO::PARAM_INT);
        $updatepkg_query->bindParam(':filehash', $param_filehash, PDO::PARAM_STR);
        $updatepkg_query->bindParam(':date', $package_file_date, PDO::PARAM_STR);
        $updatepkg_query->bindParam(':hash', $update_json_hash, PDO::PARAM_STR);
        $updatepkg_query->bindParam(':package_id', $package_id, PDO::PARAM_INT);
        $updatepkg_query->execute();
        $updatepkg_query = null;
        /*clean*/
        if (!$this->deleteDir($unzipped_dir))
          $this->addLog(true, "can't delete dir: " . $unzipped_dir);
      }
    } 
    else 
    {
      $this->addLog(true, 'Failed unzip file: ' . $zip_file);
    }
  }
  
  /*update package files info from json*/
  /*if pkg_name = '' then all*/
  public function updatePkgFiles($admin = false, $package_name = '')
  {
    $result = '';
    $this->updated_pkgs = 0;
    $this->createTempDir();
    /*for all packages with json update url*/
    $dbs = true;
    $this->db = new PDO('sqlite:' . $this->cfg_db_file);
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $sql = " SELECT p.package_id, p.Name, p.DownloadURL, p.RepositoryFileName, p.update_json_hash FROM package p WHERE p.DownloadURL <> '' ";
    if (!$admin)
    {
      $sql .= " AND p.enabled = 'Y' ";
    }
    elseif ($package_name!= '')
    {
      $sql .= " AND p.Name = " . $this->db->quote($package_name);
    }      
    $sql .= " ORDER BY p.package_id ASC "; 
    try
    {
      $pkgdata_query = $this->db->query($sql);
      $pkgdata_arr =  $pkgdata_query->fetchAll(PDO::FETCH_ASSOC);
      $pkgdata_query = null;
      $dbs = false;
      foreach ($pkgdata_arr as $pkgdata_row)
      {
        $path_info = pathinfo($pkgdata_row['DownloadURL']);
        $ext = $this->getArrayStrVal('extension', $path_info);
        if ($ext == 'json')
        {
          /*get update json*/
          $jsonheader_arr = @get_headers($pkgdata_row['DownloadURL']);
          if (!$jsonheader_arr || $jsonheader_arr[0] == 'HTTP/1.1 404 Not Found')
          {
            $this->addLog(true, $pkgdata_row['Name'] . ': update json file not exists: ' . $pkgdata_row['DownloadURL']);
          }
          else
          {
            $pkg_json = file_get_contents($pkgdata_row['DownloadURL']);
            $json_hash = md5($pkg_json);
            if ($json_hash != $pkgdata_row['update_json_hash'])
            {
              $this->updated_pkgs += 1;
              $this->addLog(false, 'update package: ' . $pkgdata_row['Name']);
              $pkg_arr = json_decode($pkg_json, true);
              $pkg_zip_url = $pkg_arr['UpdatePackageData']['DownloadZipURL'];
              $pkg_zip_tmp = $this->tmp_dir . basename($pkg_zip_url);
              
              /*get package zip file*/
              $this->addLog(false, 'download and unzip: ' . $pkg_arr['UpdatePackageData']['DownloadZipURL']);
              $zipheader_arr = @get_headers($pkg_zip_url);
              if (!$zipheader_arr || $zipheader_arr[0] == 'HTTP/1.1 404 Not Found')
              {
                $this->addLog(true, $pkgdata_row['Name'] . ': file not exists: ' . $pkg_zip_url);
              }
              else
              {
                if (file_put_contents($pkg_zip_tmp, file_get_contents($pkg_zip_url))) 
                {
                  $file_date = 0;
                  foreach ($zipheader_arr as $value)
                  {
                    if ($this->isBegins($value, 'Last-Modified: '))
                    {
                      $file_date = $this->datetimeToFloat(str_replace('Last-Modified: ', '', $value,));
                      break;
                    }
                  }
                  $this->updatePkgFileFromZip($pkg_zip_tmp, $pkgdata_row['package_id'], $pkgdata_row['RepositoryFileName'], $file_date, $json_hash);
                } 
                else 
                {
                  $this->addLog(true, $pkgdata_row['Name'] . ': failed download file: ' . $pkg_zip_url);
                }
              }
            }
          }
        }
      }
      if ($this->updated_pkgs == 0)
        $result = json_encode(array('status' => 'ok', 'message' => 'no packages to update'), JSON_PRETTY_PRINT);
    }
    catch (Exception $e)
    {
      $this->addLog(false, 'no packages defined or:' . $e->getMessage());
      $result = json_encode(array('status' => 'error', 'message' => 'no packages defined or:' . $e->getMessage()), JSON_PRETTY_PRINT);
    }
    if ($dbs)
      $pkgdata_query = null;
    
    return $result;
  }
  
  /*insert or update package info from json*/
  public function importPkgFromJson($json)
  {
    $result = '';
    $data_arr = json_decode($json, true);
    //TODO: add check json
    if ($result == '')
      $result = $this->importPkg($data_arr);
    
    return $result;
  }
  
  /*insert or update package info from array*/
  private function importPkg($data_arr)
  {
    $result = '';
    $package_id = 0;
    $enabled = 'N';
    /*list packages to update from a update.json url, will updated when added binary file exceptions*/
    $pkg_repack_arr = array();
    foreach($data_arr as $key => $value)
    {
      if ($this->isBegins($key, 'PackageData'))
      {
        $package_id = 0;
        $sql = " SELECT COUNT(1) cnt, IFNULL(MAX(package_id), 0) pid FROM package WHERE Name = ? ";
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $check_query = $this->db->prepare($sql);
        $check_query->execute([$value['Name']]);
        $package_id = $check_query->fetch(PDO::FETCH_ASSOC)['pid'];
        $check_query = null;
        if ($package_id > 0)
        {
          $sql = " UPDATE package SET Name = :name, DisplayName = :dname, Category = :category, ";
          $sql .= " CommunityDescription = :desc, ExternalDependecies = :dependecies, OrphanedPackage = :orphpkg, ";
          $sql .= " RepositoryFileName = :filename, RepositoryFileSize = :filesize, RepositoryFileHash = :filehash, ";
          $sql .= " RepositoryDate = :date, PackageBaseDir = :pkgdir, HomePageURL = :homeurl, DownloadURL = :downurl, ";
          $sql .= " SVNURL = :svnurl, enabled = :enabled WHERE package_id = :package_id ";
        }
        else
        {
          $sql = " INSERT OR IGNORE INTO package (Name, DisplayName, Category, CommunityDescription, ExternalDependecies, OrphanedPackage, ";
          $sql .= " RepositoryFileName, RepositoryFileSize, RepositoryFileHash, RepositoryDate, PackageBaseDir, HomePageURL, DownloadURL, SVNURL, ";
          $sql .= " Rating, RatingCount, enabled, update_json_hash) ";
          $sql .= " SELECT :name, :dname, :category, :desc, :dependecies, :orphpkg, :filename, :filesize, :filehash, :date, :pkgdir, :homeurl, ";
          $sql .= " :downurl, :svnurl, IFNULL((SELECT Rating FROM package WHERE Name = :name), :r), ";
          $sql .= " IFNULL((SELECT RatingCount FROM package WHERE Name = :name), :rc), :enabled, '' ";
        }
        $param_dname = $this->getArrayStrVal('DisplayName', $value, $value['Name'], true);
        $param_desc = $this->getArrayStrVal('CommunityDescription', $value);
        $param_dependecies = $this->getArrayStrVal('ExternalDependecies', $value);
        $param_orphpkg = $this->getArrayStrVal('OrphanedPackage', $value, '0', true);
        $param_homeurl = $this->getArrayStrVal('HomePageURL', $value);
        $param_downurl = $this->getArrayStrVal('DownloadURL', $value);
        $param_svnurl = $this->getArrayStrVal('SVNURL', $value);
        $tmpfn = $value['Name'] . '.zip';
        $file_name = $this->getArrayStrVal('RepositoryFileName', $value, $tmpfn, true);
        $param_r = ((($this->initmode) && (array_key_exists('Rating', $value))) ? $value['Rating'] : 0);
        $param_rc = ((($this->initmode) && (array_key_exists('RatingCount', $value))) ? $value['RatingCount'] : 0);
        $param_filesize = $value['RepositoryFileSize'];
        $param_filehash = $value['RepositoryFileHash'];
        $param_filedate = $value['RepositoryDate'];
        if ($this->initmode)
        {
          try
          {
            file_put_contents($this->cfg_main_path . $file_name, file_get_contents($this->initrepo . $file_name));
          }
          catch (Exception $e)
          {
            $this->addLog(true, 'init: could not download package file: ' . $this->initrepo . $file_name);
          }
        }
        elseif (array_key_exists('package_zip_base64', $value))
        {
          $file_body = base64_decode($value['package_zip_base64']);
          if (file_put_contents($this->cfg_main_path . $file_name, $file_body))
          {
            $param_filesize = strlen($file_body);
            $param_filehash = md5($file_body);
            $param_filedate = $this->datetimeToFloat(date('Y-m-d H:i:s'));
          }
        }
        else
        {
          $path_info = pathinfo($this->getArrayStrVal('DownloadURL', $value, ''));
          if ($this->getArrayStrVal('extension', $path_info) == 'json')
            $pkg_repack_arr[] = $value['Name'];
        }
        $param_enabled = $this->getArrayStrVal('enabled', $value, 'Y');
        if ($this->initmode)
          $_param_enabled = 'Y';
        $this->db = new PDO('sqlite:' . $this->cfg_db_file);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $insertpkg_query = $this->db->prepare($sql);
        $insertpkg_query->bindParam(':name', $value['Name'], PDO::PARAM_STR);
        $insertpkg_query->bindParam(':dname', $param_dname, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':category', $value['Category'], PDO::PARAM_STR);
        $insertpkg_query->bindParam(':desc', $param_desc, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':dependecies', $param_dependecies, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':orphpkg', $param_orphpkg, PDO::PARAM_INT);
        $insertpkg_query->bindParam(':pkgdir', $value['PackageBaseDir'], PDO::PARAM_STR);
        $insertpkg_query->bindParam(':homeurl', $param_homeurl, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':downurl', $param_downurl, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':svnurl', $param_svnurl, PDO::PARAM_STR);
        if ($package_id == 0)
        {
          $insertpkg_query->bindParam(':r', $param_r, PDO::PARAM_STR);
          $insertpkg_query->bindParam(':rc', $param_rc, PDO::PARAM_INT);
        }
        else
        {
          $insertpkg_query->bindParam(':package_id', $package_id, PDO::PARAM_INT);
        }
        $insertpkg_query->bindParam(':filename', $file_name, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':filesize', $param_filesize, PDO::PARAM_INT);
        $insertpkg_query->bindParam(':filehash', $param_filehash, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':date', $param_filedate, PDO::PARAM_STR);
        $insertpkg_query->bindParam(':enabled', $param_enabled, PDO::PARAM_STR);
        $insertpkg_query->execute();
        $insertpkg_query = null;
        if ($package_id == 0)
        {
          $sql = " SELECT package_id FROM package WHERE Name = :name ";
          $this->db = new PDO('sqlite:' . $this->cfg_db_file);
          $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
          $idpkg_query =$this->db->prepare($sql);
          $idpkg_query->bindParam(':name', $value['Name'], PDO::PARAM_STR);
          $idpkg_query->execute();
          $package_id = $idpkg_query->fetch(PDO::FETCH_ASSOC)['package_id'];
          $idpkg_query = null;
        }
      }
      elseif (($this->isBegins($key, 'PackageFiles')) && ($package_id > 0))
      {
        foreach($data_arr[$key] as $fkey => $fvalue)
        {
          $sql = " INSERT OR REPLACE INTO package_file (package_id, Name, Description, Author, License, RelativeFilePath, VersionAsString, ";
          $sql .= " LazCompatibility, FPCCompatibility, SupportedWidgetSet, PackageType, DependenciesAsString, enabled) ";
          $sql .= " SELECT :package_id, :name, :desc, :author, :license, :relpath, :version, ";
          $sql .= " IFNULL((SELECT LazCompatibility FROM package_file WHERE package_id = :package_id AND Name = :name), :lazcomp), ";
          $sql .= " IFNULL((SELECT FPCCompatibility FROM package_file WHERE package_id = :package_id AND Name = :name), :fpccomp), ";
          $sql .= " IFNULL((SELECT SupportedWidgetSet FROM package_file WHERE package_id = :package_id AND Name = :name), :sws), ";
          $sql .= " :type, :dependecies, :enabled ";
          $param_desc = $this->getArrayStrVal('Description', $fvalue);
          $param_author = $this->getArrayStrVal('Author', $fvalue);
          $param_license = $this->getArrayStrVal('License', $fvalue);
          $param_relpath = ($fvalue['RelativeFilePath'] == '') ? '' : $fvalue['RelativeFilePath'] . '/';
          $param_version = $this->getArrayStrVal('VersionAsString', $fvalue);
          $param_lazcomp = $this->getArrayStrVal('LazCompatibility', $fvalue);
          $param_fpccomp = $this->getArrayStrVal('FPCCompatibility', $fvalue);
          $param_sws = $this->getArrayStrVal('SupportedWidgetSet', $fvalue);
          $param_type = $this->getArrayStrVal('PackageType', $fvalue, '2');
          $param_dependecies = $this->getArrayStrVal('DependenciesAsString', $fvalue);
          $param_enabled = $this->getArrayStrVal('enabled', $fvalue, 'Y');
          if ($this->initmode)
            $param_enabled = 'Y';
          $this->db = new PDO('sqlite:' . $this->cfg_db_file);
          $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
          $insertfile_query =$this->db->prepare($sql);
          $insertfile_query->bindParam(':package_id', $package_id, PDO::PARAM_INT);
          $insertfile_query->bindParam(':name', $fvalue['Name'], PDO::PARAM_STR);
          $insertfile_query->bindParam(':desc', $param_desc, PDO::PARAM_STR);
          $insertfile_query->bindParam(':author', $param_author, PDO::PARAM_STR);
          $insertfile_query->bindParam(':license', $param_license, PDO::PARAM_STR);
          $insertfile_query->bindParam(':relpath', $param_relpath, PDO::PARAM_STR);
          $insertfile_query->bindParam(':version', $param_version, PDO::PARAM_STR);
          $insertfile_query->bindParam(':lazcomp', $param_lazcomp, PDO::PARAM_STR);
          $insertfile_query->bindParam(':fpccomp', $param_fpccomp, PDO::PARAM_STR);
          $insertfile_query->bindParam(':sws', $param_sws, PDO::PARAM_STR);
          $insertfile_query->bindParam(':type', $param_type, PDO::PARAM_INT);
          $insertfile_query->bindParam(':dependecies', $param_dependecies, PDO::PARAM_STR);
          $insertfile_query->bindParam(':enabled', $param_enabled, PDO::PARAM_STR);
          $insertfile_query->execute();
          $insertfile_query = null;
        }
      }
      elseif (($this->isBegins($key, 'PermmitedFiles')) && ($package_id > 0))
      {
        foreach($data_arr[$key] as $pvalue)
        {
          $sql = " INSERT INTO permmited_file (package_id, file_name) ";
          $sql .= " VALUES (:package_id, :name) ";
          $this->db = new PDO('sqlite:' . $this->cfg_db_file);
          $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
          $insertpermfile_query =$this->db->prepare($sql);
          $insertpermfile_query->bindParam(':package_id', $package_id, PDO::PARAM_INT);
          $insertpermfile_query->bindParam(':name', $pvalue, PDO::PARAM_STR);
          $insertpermfile_query->execute();
          $insertpermfile_query = null;
        }
      }
    }
    foreach ($pkg_repack_arr as $value)
    {
      $this->updatePkgFiles(true, $value);
    }
    if (!$this->initmode)
      $result = json_encode(array('status' => 'ok', 'message' => 'Package(s) imported'), JSON_PRETTY_PRINT);
    
    return $result;
  }
  
  /*export package(s) info to json*/
  /*if package name='' then export all packages*/
  public function exportPkgListJson($admin = false, $package_name = '')
  {
    $pkglist_arr = array();
    $pkgdata_i = 0; //package no
    $this->db = new PDO('sqlite:' . $this->cfg_db_file);
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $sql = " SELECT p.* FROM package p ";
    if (!$admin)
    {
      $sql .= " INNER JOIN (SELECT package_id FROM package_file WHERE enabled = 'Y' GROUP BY package_id) cf ON (p.package_id=cf.package_id) ";
      $sql .= " WHERE p.enabled = 'Y' ";
    }
    elseif ($package_name != '')
    {
      $sql .= " WHERE p.Name = " . $this->db->quote($package_name);
    }
    $sql .= " ORDER BY lower(p.Name) ASC ";
    try
    {
      $pkgdata_query = $this->db->query($sql);  
      while ($pkgdata_row = $pkgdata_query->fetch(PDO::FETCH_ASSOC))
      {
        /*generate package data*/
        $pkgdata_arr = array();
        foreach($pkgdata_row as $key=>$value)
        {
          if (($admin) || (!in_array($key, array('package_id', 'enabled', 'update_json_hash'))))
            $pkgdata_arr[$key] = $value;
        }
        $pkglist_arr['PackageData' . $pkgdata_i] = $pkgdata_arr;
        
        /*generate package files*/
        $sql = " SELECT pf.* from package_file pf WHERE pf.package_id = ? ";
        if (!$admin) 
          $sql .= " AND pf.enabled = 'Y' ";
        $sql .= " ORDER BY lower(pf.name) ASC ";
        $pkgfile_query = $this->db->prepare($sql);
        if ($pkgfile_query->execute([$pkgdata_row['package_id']]))
        {
          $pkgfiles_arr = array();
          while ($pkgfile_row = $pkgfile_query->fetch(PDO::FETCH_ASSOC))
          {
            $pkgfile_arr = array();
            foreach($pkgfile_row as $key=>$value)
            {
              if (($admin) || (!in_array($key, array('package_id', 'enabled'))))
                $pkgfile_arr[$key] = $value;
            }
            $pkgfiles_arr[] = $pkgfile_arr;
          }
          $pkglist_arr['PackageFiles' . $pkgdata_i] = $pkgfiles_arr;
        }
        
        /*generate permmited files in zip*/
        if ($admin)
        {
          $sql = " SELECT pf.* from permmited_file pf WHERE pf.package_id = ? ORDER BY lower(pf.file_name) ASC ";
          $permfile_query = $this->db->prepare($sql);
          if ($permfile_query->execute([$pkgdata_row['package_id']]))
          {
            $permfiles_arr = array();
            while ($permfile_row = $permfile_query->fetch(PDO::FETCH_ASSOC))
            {
              $pkgfiles_arr[] = $permfile_row['file_name'];
            }
            $pkglist_arr['PackagePermmitedFiles' . $pkgdata_i] = $permfiles_arr;
          }
        }
        
        $pkgdata_i += 1; 
      }
    }
    catch (Exception $e)
    {
      $this->addLog(false, 'no packages defined');
    }
    finally
    {
      $this->db = null;
    }
    $json = '';
    if ($pkgdata_i > 0)
    {
      $json = json_encode($pkglist_arr, JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);
    }
    elseif (($admin) and ($package_name != ''))
    {
      $json = json_encode(array('status' => 'error', 'message' => 'package: ' . $package_name . "don't exists"), JSON_PRETTY_PRINT);
    }
    elseif ($admin)
    {
      $json = json_encode(array('status' => 'error', 'message' => 'no defined packages'), JSON_PRETTY_PRINT);
    }
    
    return $json;
  }
  
  /*import data from $initrepo packagelist.json*/
  public function initializeDB()
  {
    $result = '';
    $cnt = 0;
    $sql = " SELECT (SELECT COUNT(1) FROM package) + (SELECT COUNT(1) FROM package_file) + ";
    $sql .= " (SELECT COUNT(1) FROM permmited_file) + (SELECT COUNT(1) FROM rating_history) cnt ";
    $this->db = new PDO('sqlite:' . $this->cfg_db_file);
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $check_query = $this->db->query($sql);
    $cnt = $check_query->fetch(PDO::FETCH_ASSOC)['cnt'];
    $check_query = null;
    if ($cnt == 0)
    {
      try
      {
        $json = file_get_contents($this->initrepo . 'packagelist.json'); 
        $this->initmode = true;
        $result = $this->importPkgFromJson($json);
        if ($result == '')
        {
          $result = $this->exportPkgListJson();
          if ($result != '')
          {
            file_put_contents($this->getJsonFileName(), $result);
          }
          else
          {
            $result = json_encode(array('status' => 'error', 'message' => 'No packages were imported'), JSON_PRETTY_PRINT);
          }
        }
      }
      catch (Exception $e)
      {
        $result = json_encode(array('status' => 'error', 'message' => 'Could not download file: ' .$this->initrepo . 'packagelist.json'), JSON_PRETTY_PRINT);
      }
    }
    else
    {
      $result = json_encode(array('status' => 'error', 'message' => 'Database is not empty'), JSON_PRETTY_PRINT);
    }
    
    return $result;
  }
}

?>