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
 
include_once './opm.php';

header("Content-Type:application/json");

$json_response = '';
$method = $_SERVER['REQUEST_METHOD'];
$cmd = (isset($_GET['command'])) ? $_GET['command'] : '';
$pkg_name = (isset($_GET['package'])) ? $_GET['package'] : '';

if (!isset($_SERVER['PHP_AUTH_USER']))
{
  $json_response = json_encode(array('status' => 'error', 'message' => 'Incorrect data'), JSON_PRETTY_PRINT);
  try
  {
    $opm = new OPM();
  }
  catch (Exception $e) { }
  switch ($method)
  {
    case 'GET':
      if ($cmd == 'rating')
      {
        $json_response = $opm->getRating($pkg_name);
      }
      elseif ($cmd == 'getcomments') 
      {
        $json_response = $opm->getComments($pkg_name);
      }      
      break;
    case 'POST':
      if (($cmd == 'setrate') && (isset($_GET['rate'])))
      {
        $json = file_get_contents('php://input');
        $json_response = $opm->setRating($pkg_name, $_GET['rate'], $json);
      } 
      break;
  }
  $opm = null;
}
else
{
  try
  {
    $opm = new OPM();
  }
  catch (Exception $e)
  {
    $json_response = json_encode(array('status' => 'error', 'message' => $e->getMessage()), JSON_PRETTY_PRINT);
  }
  if ($json_response == '')
    $json_response = $opm->checkAuth($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
  if ($json_response == '')
  {
    switch ($method)
    {
      case 'GET':
        if ($cmd == 'disable')
        {
          $json_response = $opm->disablePackage($pkg_name);
        }
        elseif ($cmd == 'initdb')
        {
          $json_response = $opm->initializeDB();
        }
        elseif ($cmd == 'ratinghistory')
        {
          $json_response = $opm->getRatingHistory($pkg_name);
        }
        elseif ($cmd == 'forceupdate')
        {
          $json_response = $opm->updatePkgFiles(true, $pkg_name);
          if ($json_response == '')
          {
            $json = $opm->exportPkgListJson();
            if ($json != '')
              file_put_contents($opm->getJsonFileName(), $json);
            $result = json_encode(array('status' => 'ok', 'message' => 'package list updated'), JSON_PRETTY_PRINT);
          }
        }
        else
        {
          $json_response = $opm->exportPkgListJson(true, $pkg_name);
        }
        break;
      case 'POST':
        $json = file_get_contents('php://input');
        $json_response = $opm->importPkgFromJson($json);
        break;
    }
  }
  $opm = null;
}

echo $json_response;

?>