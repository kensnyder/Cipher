<?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once(dirname(__FILE__) . '/../Cipher.php');

echo Cipher::init($_REQUEST['subject'], $_REQUEST['options'])->{$_REQUEST['method']}();
