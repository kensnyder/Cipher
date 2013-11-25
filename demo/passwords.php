<pre><?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once(dirname(__FILE__) . '/../Cipher.php');

Cipher::$defaultOptions['base'] = 62;

$begin = microtime(true);

foreach (range(1,3) as $i) {
	$password = uniqid();
	echo "\n$i =&gt; " . ($o = Cipher::init()->hashPassword($password)) . ' =&gt; matches? ' . (int) Cipher::init()->validatePassword($password, $o);
}

$end = round(microtime(true) - $begin,3);
echo "\nCompleted in $end seconds";