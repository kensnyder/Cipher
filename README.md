Cipher
====

Object-Oriented PHP class for encrypting, obfuscating and hashing strings with the ability to specify an arbitrary base for output

Example using default options:
```javascript
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::init($pan)->encrypt();
// "\x9CDmO\x8E>\x0FY\x9EG\xC4Mr\xF3&\x81\xD5\xCCm\xFC\x1C\xB3\x98\x13a\xD7B\xDFL'\x13\xED\xE38\xBC%\x10%\xB55l&\x8E\x81\x16\x9F\x86{"
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::init($encrypted)->decrypt();
// 4111-1111-1111-1111
```

Example setting global options:
```javascript
// convert output to base 64
Cipher::$defaultOptions['base'] = 64;
// use Rijndael 256
Cipher::$defaultOptions['cipher'] = MCRYPT_RIJNDAEL_256;
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::init($pan)->encrypt();
// "2IqbHb89kj6CpbDIeQXgdb2PGP/lC7e3xD+QbLyaX7FDhPRM5lyYRkjPMvT3yFAfK/pZh+r2immOCQLR56sL/Q=="
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::init($encrypted)->decrypt();
// 4111-1111-1111-1111
```

Example passing options:
```javascript
$options = array(
	// convert output to base 16
	'base' => 16,
	// use Rijndael 256
	'cipher' => MCRYPT_RIJNDAEL_256,
);
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::init($pan, $options)->encrypt();
// "fa4ff60081193a45f8d288358e43574c543a6c591723994313c0cabb98a7605ffdbfa4e0ae4c58b97c957708db4826cf0ad3c26ddbff5456887db66a6e3f8a10000"
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::init($encrypted, $options)->decrypt();
// 4111-1111-1111-1111
```

And perhaps most usefully, configure a set of options to reuse throughout your application:
```javascript
$options = array(
	// convert output to base 62
	'base' => 62,
	// use Rijndael 128
	'cipher' => MCRYPT_RIJNDAEL_128,
);
Cipher::createPreset('CreditCards', $options);
// encrypt a credit card number
$pan = '4111-1111-1111-1111';
$encrypted = Cipher::usePreset('CreditCard', $pan)->encrypt();
// "75akCejJpGdZhaWX5ISQPz6uKMcDSdJoTgVfuzYkiK9UpKRLp3wtPSUNWpcBMoCc4"
// Note: Encrypted strings will be different every time because iv is stored with the output
echo Cipher::usePreset('CreditCard', $encrypted)->decrypt();
// 4111-1111-1111-1111
```
