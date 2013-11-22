Cipher
====

Object-Oriented PHP class for encrypting, obfuscating and hashing strings with the ability to specify an arbitrary base for output.

The idea is that you create an object representing certain encryption settings. Then you give it strings to encrypt or decrypt.

Encryption
====

Configure a set of options to reuse throughout your application:
```php
<?php

$options = array(
	// convert output to base 62
	'base' => 62,
	// use Rijndael 128
	'cipher' => MCRYPT_RIJNDAEL_128,
);
Cipher::preset('CreditCard', $options);
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::preset('CreditCard')->encrypt($pan);
// "75akCejJpGdZhaWX5ISQPz6uKMcDSdJoTgVfuzYkiK9UpKRLp3wtPSUNWpcBMoCc4"
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::preset('CreditCard')->decrypt($encrypted);
// 4111-1111-1111-1111
```

Example using default options:
```php
<?php

// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::init()->encrypt($pan);
// "\x9CDmO\x8E>\x0FY\x9EG\xC4Mr\xF3&\x81\xD5\xCCm\xFC\x1C\xB3\x98\x13a\xD7B\xDFL'\x13\xED\xE38\xBC%\x10%\xB55l&\x8E\x81\x16\x9F\x86{"
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::init($encrypted)->decrypt();
// 4111-1111-1111-1111
```

Example setting global options:
```php
<?php

// convert output to base 64
Cipher::$defaultOptions['base'] = 64;
// use Rijndael 256
Cipher::$defaultOptions['cipher'] = MCRYPT_RIJNDAEL_256;
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::init()->encrypt($pan);
// "2IqbHb89kj6CpbDIeQXgdb2PGP/lC7e3xD+QbLyaX7FDhPRM5lyYRkjPMvT3yFAfK/pZh+r2immOCQLR56sL/Q=="
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::init($encrypted)->decrypt();
// 4111-1111-1111-1111
```

Example passing options:
```php
<?php

$options = array(
	// convert output to base 16
	'base' => 16,
	// use Rijndael 256
	'cipher' => MCRYPT_RIJNDAEL_256,
);
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::init($options)->encrypt($pan);
// "fa4ff60081193a45f8d288358e43574c543a6c591723994313c0cabb98a7605ffdbfa4e0ae4c58b97c957708db4826cf0ad3c26ddbff5456887db66a6e3f8a10000"
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::init($options)->decrypt($encrypted);
// 4111-1111-1111-1111
```

Password Hashing
====

Passwords are hashed with the latest technique: pbkdf2 algorithm

```php
<?php

$hash = Cipher::init()->passwordHash('password1');
// $hash now contains 64 characters of random salt followed by 64 characters of the hashed password
$isValid = Cipher::init()->validatePassword('password1', $hash);
// true
```