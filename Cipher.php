<?php

/**
 * Object-Oriented PHP class for encrypting, obfuscating and hashing strings with the ability to specify an arbitrary base for output
 */
class Cipher {
	
	/**
	 * The raw input string
	 * 
	 * @var string
	 */
	protected $_raw;
	
	/**
	 * The mcrypt block code "ecb", "cbc", "cfb", "ofb", "nofb" or "stream"
	 * 
	 * @var string
	 */
	protected $_blockmode;
	
	/**
	 * The MCRYPT_* constant cipher to use
	 * 
	 * @var int
	 */
	protected $_cipher;
	
	/**
	 * The character base to use (e.g. 64, 16, self:BASE_USER_SAFE)
	 * Set to false to keep all characters as is
	 * 
	 * @var string|int|bool
	 */
	protected $_base;
	
	/**
	 * The default encryption key
	 * 
	 * @var string
	 */
	protected $_key;
	
	/**
	 * The IV to use (if not supplied, one will be randomly generated and prepended to the encrypted string)
	 * Will be padded or truncated to be the right size to fit the cipher and block mode
	 * Setting the IV will cause the encrypted value to be the same every time and make the output shorter
	 * 
	 * @var string
	 */
	protected $_iv;
	
	/**
	 * The Character list to be used in base conversions for bases 2 through 64
	 * 
	 * @var string 
	 */
	protected $_base64CharList;
	
	/**
	 * If false, null bytes will be stripped (and lost) from the end of the plaintext
	 * 
	 * @var bool
	 */
	protected $_nullSafe;
	
	/**
	 * List of registered base encoder functions. 
	 * Each item is an associative array with callbacks at key "encode" and key "decode"
	 * 
	 * @var array 
	 */
	protected static $_baseEncoders = array();
	
	/**
	 * Shortcut for outputting a base 52 string that contains no vowels and no symbols thereby avoiding swear words
	 */
	const BASE_USER_SAFE = 'user_safe';
	
	/**
	 * Shortcut for outputting a base 21 string that contains no ambiguous characters such as (0 and O or 1 and l)
	 */	
	const BASE_PRINTABLE = 'printable';
	
	/**
	 * The default options for new objects
	 * 
	 * @var array
	 */
	public static $defaultOptions = array(
		'blockmode' => 'cbc',
		'cipher' => MCRYPT_RIJNDAEL_192,
		'base' => false,
		'key' => 'The Narwhals bacon at midnight',
		'iv' => false,
		'base64CharList' => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
		'nullSafe' => true
	);
	
	/**
	 * Static method for returning a Cipher instance
	 * 
	 * @param string $raw  The raw string
	 * @param array $options  Any options you want to set
	 * @return \Cipher 
	 */
	public static function init($raw = "", $options = array()) {
		return new self($raw, $options);
	}
	
	/**
	 * @param string $raw  The raw string
	 * @param array $options  Any options you want to set
	 */
	public function __construct($raw = "", $options = array()) {
		$this->_raw = $raw;
		$this->setOptions(array_merge(self::$defaultOptions, $options));
	}
	
	/**
	 * Set the mcrypt block mode for two-way encryption
	 * 
	 * @param string $mode  "ecb", "cbc", "cfb", "ofb", "nofb" or "stream"
	 * @return \Cipher 
	 */
	public function setBlockmode($mode) {
		$this->_blockmode = $mode;
		return $this;
	}
	
	/**
	 * Get the mcrypt block mode
	 * 
	 * @return int
	 */
	public function getBlockmode() {
		return $this->_blockmode;
	}
	
	/**
	 * Set the mcrypt cipher method for two-way encryption
	 * 
	 * @param type $cipher (e.g. MCRYPT_RIJNDAEL_192)
	 * @return \Cipher 
	 */
	public function setCipher($cipher) {
		$this->_cipher = $cipher;
		return $this;
	}
	
	/**
	 * Get the mcrypt cipher method
	 * 
	 * @return type 
	 */
	public function getCipher() {
		return $this->_cipher;
	}
	
	/**
	 * Set the numeric base in which to output strings
	 * 
	 * @param int|string $num
	 *   If false, do not alter output
	 *   If a number between 2 and 64, us that many characters
	 *   If self::BASE_USER_SAFE, use a base 54 string that contains no vowels or symbols to avoid swear words
	 *   If self::BASE_PRINTABLE, use a base 21 string that contains no ambiguous characters like 0 and O or 1 and l
	 * @return \Cipher 
	 */
	public function setBase($num) {
		if (isset(self::$_baseEncoders[$num])) {
			// keep as is
		}
		elseif ($num >= 2 && $num <= 64) {
			$num = (int) $num;
		}
		elseif (strlen($num)) {
			trigger_error("Cipher::setBase() Unknown base `$num`");
		}
		else {
			$num = false;
		}
		$this->_base = $num;
		return $this;
	}
	
	/**
	 * Get the numeric base for outputting strings
	 * 
	 * @return int|string
	 */
	public function getBase() {
		return $this->_base;
	}
	
	/**
	 * Set the default key for two-way encryption
	 * 
	 * @param string $key
	 * @return \Cipher 
	 */
	public function setKey($key) {
		$this->_key = $key;
		return $this;
	}
	
	/**
	 * Get the raw input string
	 * 
	 * @return string
	 */
	public function getRaw() {
		return $this->_raw;
	}
	
	/**
	 * Set the raw input string
	 * 
	 * @param string $string
	 * @return \Cipher 
	 */
	public function setRaw($string) {
		$this->_raw = $string;
		return $this;
	}
	
	/**
	 * Set the IV to use (if not supplied, one will be randomly generated and prepended to the encrypted string)
	 * Will be padded or truncated to be the right size to fit the cipher and block mode
	 * Setting the IV will cause the encrypted value to be the same every time and make the output shorter
	 * Set to falsy to generated automatically
	 * 
	 * @param string $iv
	 */
	public function setIv($iv) {
		$this->_iv = $iv;
		return $this;
	}	
	
	/**
	 * Get the current IV string
	 *
	 * @return string
	 */
	public function getIv() {
		return $this->_iv;
	}
	
	/**
	 * Set the Character List used for base-64 encoding. It defaults to the traditional set
	 * 
	 * @param string $str
	 * @return \Cipher 
	 */
	public function setBase64CharList($str) {
		$this->_base64CharList = $str;
		return $this;
	}
	
	/**
	 * Get the current Character List used for base-64 encoding
	 * 
	 * @return string
	 */
	public function getBase64CharList() {
		return $this->_base64CharList;
	}
	
	/**
	 * If true, account for null bytes that may be at the end of your plaintext
	 * 
	 * @param bool $on
	 * @return \Cipher 
	 */
	public function setNullSafe($on) {
		$this->_nullSafe = $on;
		return $this;
	}

	/**
	 * Get the current setting for handling null bytes.
	 * If true, null bytes at the end of the plaintext will be preserved
	 * 
	 * @return bool 
	 */
	public function getNullSafe() {
		return $this->_nullSafe;
	}	
	
	/**
	 * Set the given option
	 * 
	 * @param string $name  "blockmode", "cipher", "base", "key", "iv", "base64CharList", or "nullSafe"
	 * @param mixed $value
	 * @return \Cipher 
	 */
	public function setOption($name, $value) {
		if (in_array($name, array('blockmode','cipher','base','key','iv','base64CharList','nullSafe'))) {
			$this->{"_$name"} = $value;	
		}
		else {
			trigger_error("Cipher::setOption() option `$name` not valid.", E_USER_WARNING);
		}
		return $this;
	}
	
	/**
	 * Set multiple options using key-value pairs
	 * 
	 * @param array $values
	 * @return \Cipher 
	 */
	public function setOptions($values) {
		foreach ($values as $name => $value) {
			$this->setOption($name, $value);
		}
		return $this;
	}
	
	/**
	 * Get the value of a single option
	 * 
	 * @param string $name
	 * @return mixed
	 */
	public function getOption($name) {
		return isset($this->{"_$name"}) ? $this->{"_$name"} : null;
	}
	
	/**
	 * Get the value of all options
	 * 
	 * @return array
	 */
	public function getOptions() {
		$options = array();
		foreach (array('blockmode','cipher','base','key','iv','base64CharList','nullSafe') as $name) {
			$options[$name] = $this->getOption($name);
		}
		return $options;
	}
	
	/**
	 * Array of all user-defined presets. A preset is a set of options with which to create a new instance
	 * 
	 * @var array
	 */
	public static $presets = array();
	
	/**
	 * Add a preset. A preset is a set of options with which to create a new instance
	 * @example
	 *   Cipher::createPreset('ConfirmationNumber', array(
	 *     'base' => Cipher::BASE_USER_SAFE,
	 *     'key' => 'My super secret key',
	 *   ));
	 *   $encryptedConfNum = Cipher::usePreset('ConfirmationNumber', '0123456789')->encrypt();
	 *   $confNum = Cipher::usePreset('ConfirmationNumber', $encryptedConfNum)->decrypt(); 
	 * 
	 * @param string $name  The name you will use to access the preset via Cipher::usePreset($name, $text)
	 * @param array $options  See self::$defaultOptions for available options
	 */
	public static function createPreset($name, $options) {
		self::$presets[$name] = $options;
	}
	
	/**
	 * Use a preset previously defined with self::createPreset
	 * @example
	 *   Cipher::createPreset('ConfirmationNumber', array(
	 *     'base' => Cipher::BASE_USER_SAFE,
	 *     'key' => 'My super secret key',
	 *   ));
	 *   $encryptedConfNum = Cipher::usePreset('ConfirmationNumber', '0123456789')->encrypt();
	 *   $confNum = Cipher::usePreset('ConfirmationNumber', $encryptedConfNum)->decrypt();
	 * 
	 * @param type $name  The name it was defined with in Cipher::createPreset($name, $options)
	 * @param type $text  The text to encrypt/decrypt
	 * @return mixed
	 */
	public static function usePreset($name, $text) {
		return self::init($text, @self::$presets[$name]);
	}
	
	/**
	 * Return subject text if casted to a string. May be encrypted or decrypted.
	 * 
	 * @return string
	 */
	public function __toString() {
		return $this->_raw;
	}
	
	/**
	 * Return an encrypted string.
	 * 
	 * @param string $key  If not given, use $this->_key
	 *   There are actually two keys; one is $key, the other is the IV which is prepended to the output string for later reading
	 *   This two-key method produces a decryptable string that is different every time you encrypt it even with the same key
	 * @return string
	 */
	public function encrypt($key = null) {
		if ($key === null) {
			$key = $this->_key;
		}
		$keySize = mcrypt_get_key_size($this->_cipher, $this->_blockmode);
		if (strlen($key) > $keySize) {
			$key = substr($key, 0, $keySize);
		}
		$ivsize = mcrypt_get_iv_size($this->_cipher, $this->_blockmode);
		if ($this->_iv) {
			$lengthenFactor = ceil($ivsize / strlen($this->_iv));
			$iv = substr(str_repeat($this->_iv, $lengthenFactor), 0, $ivsize);
		}
		else {
			$iv = mcrypt_create_iv($ivsize);
		}
		$decrypted = (string) $this->_raw;
		$decrypted = $this->_handleNullBytesOnEncrypt($decrypted);
		$encrypted = mcrypt_encrypt($this->_cipher, $key, $decrypted, $this->_blockmode, $iv);
		if (!$this->_iv) {
			$encrypted = $iv . $encrypted;
		}
		$encrypted = $this->_baseEncode($encrypted);
		return $encrypted;
	}
	
	/**
	 * Return an decrypted string.
	 * 
	 * @param string $key  If not given, use $this->_key
	 *   There are actually two keys; one is $key, the other is the IV which is prepended to the output string for later reading
	 *   This two-key method produces a decryptable string that is different every time you encrypt it even with the same key
	 * @return string
	 */	
	public function decrypt($key = null) {
		if (strlen($this->_raw) == 0) {
			return '';
		}
		if ($key === null) {
			$key = $this->_key;
		}
		$keySize = mcrypt_get_key_size($this->_cipher, $this->_blockmode);
		if (strlen($key) > $keySize) {
			$key = substr($key, 0, $keySize);
		}		
		$str = $this->_raw;
		$str = $this->_baseDecode($str);
		$ivsize = mcrypt_get_iv_size($this->_cipher, $this->_blockmode);
		if ($this->_iv) {
			$lengthenFactor = ceil($ivsize / strlen($this->_iv));
			$iv = substr(str_repeat($this->_iv, $lengthenFactor), 0, $ivsize);			
			$encrypted = $str;
		}
		else {
			$iv = substr($str, 0, $ivsize);
			$encrypted = substr($str, $ivsize);
		}
		$decrypted = mcrypt_decrypt($this->_cipher, $key, $encrypted, $this->_blockmode, $iv);
		$decrypted = $this->_handleNullBytesOnDecrypt($decrypted);
		return $decrypted;
	}
	
	/**
	 * If the nullSafe option is true, preserve trailing null bytes
	 * What we actually to is read the prepended number that represents the count of trailing null bytes.
	 * The number and plaintext are delimited by \x01
	 * 
	 * @param string $decrypted
	 * @return string 
	 */
	protected function _handleNullBytesOnDecrypt($decrypted) {
		if ($decrypted == '') {
			return '';
		}		
		$decrypted = rtrim($decrypted, "\x00");
		if ($this->_nullSafe && ($pos = strpos($decrypted, "\x01"))) {
			// we may need to add some null bytes back on the end
			$numNullBytes = (int) substr($decrypted, 0, $pos);
			if ($numNullBytes > 0) {
				$decrypted .= str_repeat("\x00", $numNullBytes);
			}
			$decrypted = substr($decrypted, strlen($numNullBytes) + 1);
		}
		return $decrypted;
	}
	
	/**
	 * If the nullSafe option is true, preserve trailing null bytes
	 * What we actually do is prepend a number representing the count of trailing null bytes followed by \x01
	 * 
	 * @param string $decrypted
	 * @return string 
	 */
	protected function _handleNullBytesOnEncrypt($decrypted) {
		if ($decrypted == '') {
			return '';
		}
		if ($this->_nullSafe) {
			// find the number of trailing null bytes
			$length = strlen($decrypted);
			$numNullBytes = 0;
			while (--$length) {
				if ($decrypted{$length} == "\x00") {
					$numNullBytes++;
				}
				else {
					break;
				}
			}
			// prepend number of trailing null bytes
			$decrypted = $numNullBytes . "\x01" . $decrypted;
		}
		return $decrypted;		
	}
	
	/**
	 * Simpler encryption routine that produces the same output every time the key is used
	 * 
	 * @param string $key  If not given, use $this->_key
	 * @return string
	 */
	public function obfuscate($key = null) {
		if ($key === null) {
			$key = $this->_key;
		}
		$key = base64_encode($key);
		$keylen = strlen($key);
		$str = base64_encode($this->_raw);
		$strlen = strlen($str);
		$buffer = '';
		for ($i = 0; $i < $strlen; $i++) {
			$strord = ord(substr($str, $i, 1));
			$keyord = ord(substr($key, $i % $keylen, 1));
			$buffer .= chr($strord ^ $keyord);
		}
		$buffer = $this->_baseEncode($buffer);
		return $buffer;
	}
	
	/**
	 * Simpler decryption routine that produces the same output every time the key is used
	 * 
	 * @param string $key  If not given, use $this->_key
	 * @return string
	 */	
	public function unobfuscate($key = null) {
		if ($key === null) {
			$key = $this->_key;
		}
		$str = $this->_raw;
		$str = $this->_baseDecode($str);	
		$key = base64_encode($key);
		$keylen = strlen($key);
		$strlen = strlen($str);
		$buffer = '';
		for ($i = 0; $i < $strlen; $i++) {
			$strord = ord(substr($str, $i, 1));
			$keyord = ord(substr($key, $i % $keylen, 1));
			$buffer .= chr($strord ^ $keyord);
		}
		$buffer = base64_decode($buffer);
		return $buffer;
	}
	
	/**
	 * Produce a random hash of the given length
	 * 
	 * @param int $length
	 * @return string 
	 */
	public function random($length = 40) {
		$buffer = '';
		while (strlen($buffer) < $length) {
			$str = sha1('sha1', $this->_raw . microtime() . uniqid());
			$str = $this->_baseEncode($str);
			$buffer .= $str;
		}
		return substr($buffer, 0, $length);
	}
	
	/**
	 * Static method to produce a random hash of the given length and base
	 * 
	 * @param int $length
	 * @param int|string $base
	 * @return string
	 */
	public static function slug($length = 40, $base = 'user_safe') {
		return self::init()->setBase($base)->random($length);
	}
	
	/**
	 * Return a hash using the given method (e.g. sha1, in the set base)
	 * 
	 * @param string $method  (sha1/sha256/md5)
	 * @return string 
	 */
	public function hash($method = 'sha1') {
		$str = $this->_raw;
		$str = $method($str);
		$str = $this->_baseEncode($str);
		return $str;
	}
	
	/**
	 * Register an encoder/decoder pair for converting strings in arbitrary bases
	 * 
	 * @param string $name  The name that is used by ->setBase($name)
	 * @param callback $encoder  Callback that takes unencoded string and returns encoded string
	 * @param callback $decoder  Callback that takes encoded string and returns unencoded string
	 */
	public static function registerBaseEncoder($name, $encoder, $decoder) {
		self::$_baseEncoders[$name] = array('encode' => $encoder, 'decode' => $decoder);
	}
	
	/**
	 * Remove a previously registered string encoder/decoder pair
	 * 
	 * @param string $name 
	 */
	public static function unregisterBaseEncoder($name) {
		unset(self::$_baseEncoders[$name]);
	}
	
	/**
	 * Get the list of registered base encoders
	 * 
	 * @return array
	 */
	public static function getBaseEncoders() {
		return self::$_baseEncoders;
	}
	
	/**
	 * Get a single base encoder by name. Returns null if not found
	 * 
	 * @param string $name
	 * @return array  Null if not found
	 */
	public static function getBaseEncoder($name) {
		if (!isset(self::$_baseEncoders[$name])) {
			return null;
		}
		return self::$_baseEncoders[$name];
	}
	
	/**
	 * Helper function for encoding strings in the set base
	 * 
	 * @param string $str
	 * @return string
	 */
	protected function _baseEncode($str) {
		if ($this->_base) {
			$str = base64_encode($str);			
			//$str = rtrim($str, '='); // equals signs are just padding that php doesn't need to decode
		}
		if (isset(self::$_baseEncoders[$this->_base])) {
			$str = call_user_func(self::$_baseEncoders[$this->_base]['encode'], $str);
		}		
		elseif ($this->_base >= 2 && $this->_base < 64) {
			// arbitrary base
			$str = self::baseConvertString($str, $this->_base64CharList, substr($this->_base64CharList,0,$this->_base));
		}
		return $str;		
	}

	/**
	 * Helper function for decoding strings in the set base
	 * 
	 * @param string $str
	 * @return string
	 */	
	protected function _baseDecode($str) {
		if (isset(self::$_baseEncoders[$this->_base])) {
			$str = call_user_func(self::$_baseEncoders[$this->_base]['decode'], $str);
		}
		elseif ($this->_base >= 2 && $this->_base < 64) {
			// arbitrary base
			$str = self::baseConvertString($str, substr($this->_base64CharList,0,$this->_base), $this->_base64CharList);
		}
		if ($this->_base) {
			$str = base64_decode($str);
		}		
		return $str;
	}
	
	/**
	* Convert a string to a string in another base
	* Note: the bases are only limited to the length of $sFromMap and $sToMap and $sNumber can be any length (up to base 256)
	* 
	* @param string $sNumber  the string number which to convert
	* @param string $sFromMap  the ascii string to decode the string
	* @param string $sTomMap  the ascii string to encode the string
	* @return string
	* @example
	* Cipher::baseConvertString('0010','01234567','abcdefghij'); // aai
	*/
	public static function baseConvertString($sNumber, $sFromMap, $sToMap) {
		// interpret subject as a string
		$sNumber = (string) $sNumber;
		// get our lengths
		$iFromBase = strlen($sFromMap);
		$iToBase = strlen($sToMap);
		$length = strlen($sNumber);
		// build an array of numbers based on positions in the from and to maps
		$aDigits = array();
		for ($i = 0; $i < $length; $i++) {
			$aDigits[$i] = strpos($sFromMap, $sNumber{$i});
		}
		// start our buffer
		$result = '';
		do { // loop until entire number is converted
			$divide = 0;
			$newlen = 0;
			for ($i = 0; $i < $length; $i++) { // perform division manually (which is why this works with big numbers)
				$divide = ($divide * $iFromBase) + $aDigits[$i];
				if ($divide >= $iToBase) {
					$aDigits[$newlen++] = floor($divide / $iToBase);
					$divide = $divide % $iToBase;
				}
				elseif ($newlen > 0) {
					$aDigits[$newlen++] = 0;
				}
			}
			$length = $newlen;
			$result = $sToMap{$divide} . $result;
		} while ($newlen != 0);
		// pad with the leading zeros they came in with
		$fromZero = $sFromMap{0};
		if (preg_match('/^' . preg_quote($fromZero) . '+/', $sNumber, $match)) {
			$toZero = $sToMap{0};
			$zeroPad = str_repeat($toZero, strlen($match[0]));
			$result = $zeroPad . $result;
		}
		trim($result, "\x00");
		return $result;	
	}
	
}

//
// Register some cool base encoders
//
Cipher::registerBaseEncoder(Cipher::BASE_USER_SAFE, 
	// remove all vowels to avoid bad words and remove symbols for simplicity
	create_function('$str', "
		return Cipher::baseConvertString(\$str,
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
			'0123456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
		);
	"), 
	create_function('$str', "
		return Cipher::baseConvertString(\$str,
			'0123456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ',
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/'
		);
	")
);

Cipher::registerBaseEncoder(Cipher::BASE_PRINTABLE, 
	// keep only characters that are highly visually distinct
	// e.g. a password that you might right down
	create_function('$str', "
		return Cipher::baseConvertString(\$str,
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
			'3467bcdfhjkmnpqrtvwxy'
		);
	"), 
	create_function('$str', "
		return Cipher::baseConvertString(\$str,
			'3467bcdfhjkmnpqrtvwxy',
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/'
		);
	")
);
