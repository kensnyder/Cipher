<?php

/**
 * Class for encrypting, obfuscating and hashing strings with the ability to specify an arbitrary base for output
 */
class Cipher {
	
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
	 * The character base to use (e.g. 64, 16, Cipher::BASE_USER_SAFE)
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
	 * The IV to use (if falsy, one will be randomly generated and prepended to the encrypted string)
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
	protected $_baseCharList;
	
	/**
	 * If false, null bytes will be stripped (and lost) from the end of the plaintext. Default is true.
	 * 
	 * @var bool
	 */
	protected $_nullSafe;

	/**
	 *
	 * @var string  An algorithm to pass to hash_pbkdf2() - see http://us2.php.net/hash-pbkdf2
	 * to see the list of supported algorithms on your server, run `php -r 'print_r(hash_algos());'`
	 */
	protected $_pbkdf2Algo;
	
	/**
	 *
	 * @var int  The number of iterations to use in hash_pbkdf2() - see http://us2.php.net/hash-pbkdf2
	 * defaults to 100000
	 */
	protected $_pbkdf2Iterations;
	
	/**
	 *
	 * @var int  The number of bytes hash_pbkdf2() should use - see http://us2.php.net/hash-pbkdf2
	 * @example  32 bytes will give a hex-encoded string of length 64. Default is 32
	 */
	protected $_pbkdf2Bytes;
	
	/**
	 * List of registered base encoder functions. 
	 * Each item is an associative array with callbacks at key "encode" and key "decode"
	 * 
	 * @var array 
	 */
	protected static $_baseEncoders = array();
	
	/**
	 * Array of all user-defined presets. A preset is a set of options with which to create a new instance
	 * 
	 * @var array
	 */
	public static $presets = array();	
	
	/**
	 * Shortcut for outputting a base 52 string that contains no vowels and no symbols thereby avoiding swear words
	 */
	const BASE_USER_SAFE = 'user_safe';
	
	/**
	 * Shortcut for outputting a base 21 string that contains no ambiguous characters such as (0 and O or 1 and l)
	 */	
	const BASE_PRINTABLE = 'printable';
	
	/**
	 * Shortcut for outputting a base 95 string that contains all printable ascii characters + space
	 */	
	const BASE_ASCII = 'ascii';
	
	/**
	 * The default options for new objects
	 * 
	 * @var array
	 */
	public static $defaultOptions = array(
		'blockmode' => 'cbc',
		'cipher' => MCRYPT_RIJNDAEL_192,
		'base' => false,
		'key' => 'obfuscate me',
		'iv' => false,
		'baseCharList' => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/ !"#$%&\'()*,-.:;<=>?@[\\]^_`{|}~',
		'nullSafe' => true,
		'pbkdf2Algo' => 'sha256',
		'pbkdf2Iterations' => 100000,
		'pbkdf2Bytes' => 32,
	);
	
	/**
	 * The names of all the supported options (see Cipher::$defaultOptions)
	 * @var array
	 */
	protected $_optionNames = array(
		'blockmode',
		'cipher',
		'base',
		'key',
		'iv',
		'baseCharList',
		'nullSafe',
		'pbkdf2Algo',
		'pbkdf2Iterations',
		'pbkdf2Bytes',
	);
	
	/**
	 * Static method for returning a Cipher instance
	 * 
	 * @param array $options  Any options you want to set
	 * @return \Cipher 
	 */
	public static function init($options = array()) {
		return new self($options);
	}
	
	/**
	 * @param string $raw  The raw string
	 * @param array $options  Any options you want to set
	 */
	public function __construct($options = array()) {
		$this->setOptions(array_merge(static::$defaultOptions, $options));
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
	 *   If a number between 2 and 95, use that many characters
	 *   If static::BASE_USER_SAFE, use a base 54 string that contains no vowels or symbols to avoid swear words
	 *   If static::BASE_PRINTABLE, use a base 21 string that contains no ambiguous characters like 0 and O or 1 and l
	 * @return \Cipher 
	 */
	public function setBase($num) {
		if (isset(static::$_baseEncoders[$num])) {
			// keep as is
		}
		elseif ($num >= 2 && $num <= 95) {
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
	 * Set the pbkdf2 algorithm, for a list of supported algorithms on a server, run hash_algos()
	 * @param string $algo  The name of the algorithm (sha256 is recommended and default)
	 * @return \Cipher
	 * @throws Exception if algorithm is unknown
	 */
	public function setPbkdf2Algo($algo) {
		if (!in_array($algo, hash_algos(), true)) {
			throw new Exception("Unknown pbkdf2 algorithm `$algo`. Allowed algorithms on this server: " . join(', '.hash_algos()));
		}
		$this->_pbkdf2Algo = $algo;
		return $this;
	}
	
	/**
	 * Get the currently set pbkdf2 algorithm
	 * @return string
	 */
	public function getPbkdf2Algo() {
		return $this->_pbkdf2Algo;
	}
	
	/**
	 * Set the number of iterations to run in Cipher::hashPassword(). Higher numbers mean more computation time and harder to crack hashes
	 * @param int $num
	 * @return \Cipher
	 */
	public function setPbkdf2Iterations($num) {
		$this->_pbkdf2Iterations = (int) $num;
		return $this;
	}
	
	/**
	 * Get the number of iterations to run in Cipher::hashPassword()
	 * @return int
	 */
	public function getPbkdf2Iterations() {
		return $this->_pbkdf2Iterations;
	}
	
	/**
	 * Set the byte length of the output for Cipher::hashPassword(). 32 bytes results in a 64-character string in base 16. 32 is default
	 * @param int $num
	 * @return \Cipher
	 */
	public function setPbkdf2Bytes($num) {
		$this->_pbkdf2Bytes = $num;
		return $this;
	}
	
	/**
	 * Get the current value for pbkdf2 bytes
	 * @return int
	 */
	public function getPbkdf2Bytes() {
		return $this->_pbkdf2Bytes;
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
		$this->_baseCharList = $str;
		return $this;
	}
	
	/**
	 * Get the current Character List used for base-64 encoding
	 * 
	 * @return string
	 */
	public function getBase64CharList() {
		return $this->_baseCharList;
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
	 * @param string $name  "blockmode", "cipher", "base", "key", "iv", "baseCharList", or "nullSafe"
	 * @param mixed $value
	 * @return \Cipher 
	 */
	public function setOption($name, $value) {
		if (in_array($name, $this->_optionNames)) {
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
		foreach ($this->_optionNames as $name) {
			$options[$name] = $this->getOption($name);
		}
		return $options;
	}
	
	/**
	 * Add or access a preset. A preset is a set of options with which to create a new instance
	 * @example
	 *   Cipher::preset('ConfirmationNumber', array(
	 *     'base' => Cipher::BASE_USER_SAFE,
	 *     'key' => 'My super secret key',
	 *   ));
	 *   $encryptedConfNum = Cipher::preset('ConfirmationNumber')->encrypt('0123456789');
	 *   $confNum = Cipher::preset('ConfirmationNumber')->decrypt($encryptedConfNum); 
	 * 
	 * @param string $name  The name you will use to access the preset
	 * @param array [$options]  See static::$defaultOptions for available options. If not given, a Cipher instance is returned
	 */
	public static function preset($name, $options = array()) {
		if (is_array($options)) {
			static::$presets[$name] = $options;
			return null;
		}
		if (!isset(static::$presets[$name])) {
			throw new Exception("Cipher preset named `$name` was not found.");
		}
		return static::init(static::$presets[$name]);
	}
	
	/**
	 * Return an encrypted string.
	 * 
	 * @param string $decrypted  The plain-text string
	 * @return string
	 */
	public function encrypt($decrypted) {
		$key = $this->_key;
		$keySize = mcrypt_get_key_size($this->_cipher, $this->_blockmode);
		if (strlen($key) > $keySize) {
			$key = substr($key, 0, $keySize);
		}
		$ivsize = mcrypt_get_iv_size($this->_cipher, $this->_blockmode);
		if (empty($this->_iv)) {			
			$iv = mcrypt_create_iv($ivsize, MCRYPT_DEV_URANDOM);
		}
		else {
			$lengthenFactor = ceil($ivsize / strlen($this->_iv));
			$iv = substr(str_repeat($this->_iv, $lengthenFactor), 0, $ivsize);
		}
		$decrypted = $this->_handleNullBytesOnEncrypt($decrypted);
		$encrypted = mcrypt_encrypt($this->_cipher, $key, $decrypted, $this->_blockmode, $iv);
		if (empty($this->_iv)) {
			$encrypted = $iv . $encrypted;
		}
		$encrypted = $this->_baseEncode($encrypted);
		return $encrypted;
	}
	
	/**
	 * Return a decrypted string.
	 * 
	 * @param string $str  The encrypted string
	 *   There are actually two keys; one is $this->_key, the other is the IV which is prepended to the output string for later reading
	 *   This two-key method produces a decryptable string that is different every time you encrypt it even with the same key
	 * @return string
	 */	
	public function decrypt($str) {
		if (strlen($str) == 0) {
			return '';
		}
		$key = $this->_key;
		$keySize = mcrypt_get_key_size($this->_cipher, $this->_blockmode);
		if (strlen($key) > $keySize) {
			$key = substr($key, 0, $keySize);
		}		
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
	 * Get a random string of hex characters with the given byte length
	 * @param int $bytes  The number of bytes. E.g. 32 bytes will produce a 64-character string
	 * @return string  Hex-encoded bytes
	 */
	public static function random($bytes) {
		return bin2hex(openssl_random_pseudo_bytes($bytes));
	}	
	
	/**
	 * Static method to produce a unique md5 in base52 that excludes vowels
	 * @param int $bytes  The number of bytes the result should be
	 * @return string  Random number in base52
	 */
	public static function slug($bytes) {
		return Cipher::baseConvertMapped(
			static::random($bytes),
			'0123456789abcdef',
			'0123456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
		);
	}
	
	/**
	 * Return a hash using the given algorithm (e.g. sha1, in the set base)
	 * 
	 * @param string $method  (sha1/sha256/md5)
	 * @return string 
	 */
	public function hash($str, $method = 'sha256') {
		$str = hash_hmac($method, $str);
		$str = $this->_baseEncode($str);
		return $str;
	}
	
	/**
	 * Register an encoder/decoder pair for converting strings in arbitrary bases
	 * 
	 * @param string $name  The name that is used by ->setBase($name)
	 * @param callback $methods[encoder]  Callback that takes unencoded string and returns encoded string
	 * @param callback $methods[decoder]  Callback that takes encoded string and returns unencoded string
	 */
	public static function registerBaseEncoder($name, $methods) {
		static::$_baseEncoders[$name] = $methods;
	}
	
	/**
	 * Remove a previously registered string encoder/decoder pair
	 * 
	 * @param string $name 
	 */
	public static function unregisterBaseEncoder($name) {
		unset(static::$_baseEncoders[$name]);
	}
	
	/**
	 * Get the list of registered base encoders
	 * 
	 * @return array
	 */
	public static function getBaseEncoders() {
		return static::$_baseEncoders;
	}
	
	/**
	 * Get a single base encoder by name. Returns null if not found
	 * 
	 * @param string $name
	 * @return array  Null if not found
	 */
	public static function getBaseEncoder($name) {
		if (!isset(static::$_baseEncoders[$name])) {
			return null;
		}
		return static::$_baseEncoders[$name];
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
			$str = rtrim($str, '='); // equals signs are just padding that php doesn't need to decode
		}
		if (isset(static::$_baseEncoders[$this->_base])) {
			$str = call_user_func(static::$_baseEncoders[$this->_base]['encode'], $str);
		}		
		elseif ($this->_base >= 2 && $this->_base < 95) {
			// arbitrary base
			$str = static::baseConvertMapped($str, $this->_baseCharList, substr($this->_baseCharList,0,$this->_base));
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
		if (isset(static::$_baseEncoders[$this->_base])) {
			$str = call_user_func(static::$_baseEncoders[$this->_base]['decode'], $str);
		}
		elseif ($this->_base >= 2 && $this->_base < 95) {
			// arbitrary base
			$str = static::baseConvertMapped($str, substr($this->_baseCharList,0,$this->_base), $this->_baseCharList);
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
	* Cipher::baseConvertMapped('0010','01234567','abcdefghij'); // aai
	*/
	public static function baseConvertMapped($sNumber, $sFromMap, $sToMap) {
		// interpret subject as a string
		$sNumber = (string) $sNumber;
		// get our lengths
		$iFromBase = strlen($sFromMap);
		$iToBase = strlen($sToMap);
		$length = strlen($sNumber);
		// build an array of numbers based on positions in the from and to maps
		$aDigits = array();
		for ($i = 0; $i < $length; $i++) {
			$aDigits[$i] = strpos($sFromMap, substr($sNumber, $i, 1));
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
			$result = substr($sToMap, $divide, 1) . $result;
		} while ($newlen != 0);
		// pad with the leading zeros they came in with
		$fromZero = substr($sFromMap, 0, 1);
		if (preg_match('/^' . preg_quote($fromZero) . '+/', $sNumber, $match)) {
			$toZero = substr($sToMap, 0, 1);
			$zeroPad = str_repeat($toZero, strlen($match[0]));
			$result = $zeroPad . $result;
		}
		trim($result, "\x00");
		return $result;	
	}
	
	/**
	 * 
	 * @param string $stringNumber  A string containing printable ascii characters (0x20 through 0x7e)
	 * @param int $fromBase  A base between 2 and 95
	 * @param int $toBase  A base between 2 and 95
	 * @return string  The converted string
	 * @throws Exception
	 */
	public static function baseConvert($stringNumber, $fromBase, $toBase) {
		$stringNumber = (string) $stringNumber;
		$fromBase = (int) $fromBase;
		$toBase = (int) $toBase;
		if ($fromBase < 2 || $fromBase > 95 || $toBase < 2 || $toBase > 95) {
			throw new Exception("Error converting number; bases must be between 2 and 95");
		}
		if ($fromBase == $toBase) {
			return $stringNumber;
		}
		static $map = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/ !"#$%&\'()*,-.:;<=>?@[\\]^_`{|}~';
		return static::baseConvertMapped($stringNumber, substr($map, 0, $fromBase), substr($map, 0, $toBase));
	}
	
	/**
	 * Obfuscate a string
	 * That is, create a string in the form "$payload-$hashOfPayload" 
	 *   where $hashOfPayload is generated from a sha1 of $payload and $this->_key for salt
	 *   Then base encode it so it has no dash
	 * Then, using unobfuscate, we base decode it into its dashed form
	 *   And check that the payload hash matches
	 * Useful for vanilla attacks where payload is not secret, but it might be an ID
	 *   That would allow an attacker to simply increment the ID
	 * @param string $string
	 * @param int [$length=7]  Uses this many characters of the hash
	 *   there is no need that the hash be unique, just that the payload-hash combination is unique
	 * @return string
	 */
	public function obfuscate($string, $length = 7) {
		$salt = $this->_key;
		$hash = sha1($string . $salt);
		$hashPart = substr($hash, 0, $length);
		$token = $this->_baseEncode($string . '-' . $hashPart);
		return $token;
	}

	/**
	 * Retreive a value that was obfuscated using $this->obfuscate()
	 * @param string $string
	 * @param int [$length=7]
	 * @return string
	 */
	public function unobfuscate($string, $length = 7) {
		$salt = $this->_key;
		$decoded = $this->_baseDecode($string);
		list($value, $token) = explode('-', $decoded);
		$expectedToken = substr(sha1($value . $salt), 0, $length);
		return $token == $expectedToken ? $value : null;
	}

	/**
	 * Hash a password using PBKDF2 and random salt
	 * Under default options, it returns a 128-character string 
	 * that contains the salt and the computed hash
	 * @param string $password  The password to hash
	 * @param string [$salt]  The salt to use. If not given, a random salt is used. Random salt is recommended.
	 * @return string  The salt and hash concatenated. Send to $this->validatePassword to check it
	 */
	public function hashPassword($password, $salt = null) {		
		$salt = $salt ?: static::random($this->_pbkdf2Bytes);
		$hash = hash_pbkdf2(
			$this->_pbkdf2Algo,
			$password,
			$salt,
			$this->_pbkdf2Iterations,
			$this->_pbkdf2Bytes,
			false
		);
		return $salt . $hash;
	}

	/**
	 * Validate a password against the given string consisting of salt concatenated with a hash
	 * @param string $password  The password to check
	 * @param string $againstSaltAndHash  The salt + hash string (that was returned from hashPassword) to which to compare
	 * @return bool  True if the password matches the salt
	 */
	public function validatePassword($password, $againstSaltAndHash) {
		$len = $this->_pbkdf2Bytes * 2;
		$usedSalt = substr($againstSaltAndHash, 0, $len);
		$computedHash = $this->hashPassword($password, $usedSalt);
		return ($computedHash == $againstSaltAndHash);
	}

}

/*
 * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
 * $algorithm - The hash algorithm to use. Recommended: SHA256
 * $password - The password.
 * $salt - A salt that is unique to the password.
 * $count - Iteration count. Higher is better, but slower. Recommended: At least 1024.
 * $key_length - The length of the derived key in bytes.
 * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
 * Returns: A $key_length-byte key derived from the password and salt.
 *
 * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
 *
 * This implementation of PBKDF2 was originally created by defuse.ca
 * With improvements by variations-of-shadow.com
 */
if (!function_exists('hash_pbkdf2')) {
	function hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
	{
		$algorithm = strtolower($algorithm);
		if(!in_array($algorithm, hash_algos(), true))
			die("PBKDF2 ERROR: Invalid hash algorithm `$algorithm`.");
		if($count <= 0 || $key_length <= 0)
			die('PBKDF2 ERROR: Invalid parameters.');

		$hash_length = strlen(hash($algorithm, "", true));
		$block_count = ceil($key_length / $hash_length);

		$output = "";
		for($i = 1; $i <= $block_count; $i++) {
			// $i encoded as 4 bytes, big endian.
			$last = $salt . pack("N", $i);
			// first iteration
			$last = $xorsum = hash_hmac($algorithm, $last, $password, true);
			// perform the other $count - 1 iterations
			for ($j = 1; $j < $count; $j++) {
				$xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
			}
			$output .= $xorsum;
		}

		if($raw_output)
			return substr($output, 0, $key_length);
		else
			return bin2hex(substr($output, 0, $key_length));
	}
}

//
// Register some cool base encoders
//
Cipher::registerBaseEncoder(Cipher::BASE_USER_SAFE, array(
	// remove all vowels to avoid bad words and remove symbols for simplicity
	'encode' => function($str) {
		return Cipher::baseConvertMapped($str,
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
			'0123456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
		);
	}, 
	'decode' => function($str) {
		return Cipher::baseConvertMapped($str,
			'0123456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ',
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/'
		);
	})
);

Cipher::registerBaseEncoder(Cipher::BASE_PRINTABLE, array(
	// keep only characters that are highly visually distinct
	// e.g. a password that you might right down
	'encode' => function($str) {
		return Cipher::baseConvertMapped($str,
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
			'3467bcdfhjkmnpqrtvwxy'
		);
	}, 
	'decode' => function($str) {
		return Cipher::baseConvertMapped($str,
			'3467bcdfhjkmnpqrtvwxy',
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/'
		);
	})
);

Cipher::registerBaseEncoder(Cipher::BASE_ASCII, array(
	// all 95 printable ascii characters + space
	'encode' => function($str) {
		return Cipher::baseConvertMapped($str,
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/ !"#$%&\'()*,-.:;<=>?@[\\]^_`{|}~',
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/'
		);
	}, 
	'decode' => function($str) {
		return Cipher::baseConvertMapped($str,
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/',
			'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/ !"#$%&\'()*,-.:;<=>?@[\\]^_`{|}~'
		);
	})
);
