<?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once(dirname(__FILE__) . '/../Cipher.php');
Cipher::$defaultOptions['cipher'] = MCRYPT_RIJNDAEL_256;


$out = Cipher::init($_REQUEST['options'])->{$_REQUEST['method']}($_REQUEST['subject']);

if (!$_REQUEST['options']['base']) {
	$out = preg_replace_callback('/[\x00-\x20\x7F-\xFF]/', 'make_printable', $out);
}

echo $out;


function make_printable($match) {
	$hex = dechex( ord($match[0]) );
	$hex = strtoupper($hex);
	if (strlen($hex) == 1) {
		return '\\x0' . $hex;
	}
	else {
		return '\\x' . $hex;
	}
}
