<pre><?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once(dirname(__FILE__) . '/../Cipher.php');

Cipher::$defaultOptions['base'] = 62;

$begin = microtime(true);

foreach (range(1000,1050) as $i) {
	echo "\n$i =&gt; " . ($o = Cipher::init()->encrypt($i)) . ' =&gt; ' . Cipher::init()->decrypt($o);
}

$end = round(microtime(true) - $begin,3);
echo "\nCompleted in $end seconds";