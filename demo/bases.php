<pre><?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once(dirname(__FILE__) . '/../Cipher.php');

$begin = microtime(true);

$tests = array(
	array('0010', 2, 10), // 002
	array('01111', 2, 16), // 0f
	array('010001', 2, 16), // 011
	array('The quick brown fox jumped over the lazy dog', 65, 95),
	array('1f6b5f11a791cfbccd347599ae29c7005edf121ad3f2bbf75e510354b231211fe424ccfb57be2775d6b23916d8c0c40f19c67d48c37f1fda87166f065230cded', 16, 17),
	array('1f6b5f11a791cfbccd347599ae29c7005edf121ad3f2bbf75e510354b231211fe424ccfb57be2775d6b23916d8c0c40f19c67d48c37f1fda87166f065230cded', 16, 95),
	array('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16, 95),
	array('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16, 17),
);

// padd up to 1000 tests
foreach (range(1234567, 1235567 - count($tests)) as $i) {
	$tests[] = array($i, 10, 95);
}

foreach ($tests as $test) {
	$res = Cipher::baseConvert($test[0], $test[1], $test[2]);
	echo "\nCipher::baseConvert('{$test[0]}', {$test[1]}, {$test[2]}) =&gt; \"" . htmlspecialchars($res) . '"';
	echo " *** and back =&gt; \"" . Cipher::baseConvert($res, $test[2], $test[1]) . '"';
}

$end = round(microtime(true) - $begin,3);
echo "\n\nCompleted in $end seconds";