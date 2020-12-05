# Two Factor Authentication

A two-factor authentication class written in PHP that works with Authy and Google Authenticator

## Installation

Extract the downloaded zip in your directory

## Usage

```php
<?php
require_once 'Authenticator.php';

$auth = new Sebcodes\Authenticator();

//Create a Secret Key
$secret = $auth->createSecret();

//Create an QR-Code for the Authenticator App (optional)
$qrCode = $auth->createQRCode('Test-App', $secret);

//Generate a key to simulate a user input
$code = $auth->getCode($secret);

//check if the code is valid, instead of code you can also use your user input
$valid = $ga->verifyCode($secret, $code, 2);
if ($valid) {
    echo 'Grant access';
} else {
    echo 'Access failed';
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
