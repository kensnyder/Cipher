<pre><?php

require_once(dirname(__FILE__) . '/../Cipher.php');

Cipher::$defaultOptions['base'] = 95;

foreach (range(1000,1050) as $i) {
	echo "\n$i =&gt; " . ($o = Cipher::init($i)->encrypt()) . ' =&gt; ' . Cipher::init($o)->decrypt();
}