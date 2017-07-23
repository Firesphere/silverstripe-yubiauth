# status
[![Scrutinizer Status](https://scrutinizer-ci.com/g/Firesphere/silverstripe-yubiauth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Firesphere/silverstripe-yubiauth)
[![License](https://poser.pugx.org/firesphere/yubiauth/license?format=flatS)](https://packagist.org/packages/firesphere/yubiauth)
[![TravisCI Status](https://travis-ci.org/Firesphere/silverstripe-yubiauth.svg?branch=master)](https://travis-ci.org/Firesphere/silverstripe-yubiauth/)

# WARNING

Current SS4 branch is broken, based on the refactoring of authentication inside the core.

Until that refactor is completed, the SS4 version of this module will not work properly.

# Usage

Install the module using composer:
```
composer require firesphere\yubiauth
```

## Configuration

Configure your ClientID and API key in your environment file.

```
define('YUBIAUTH_CLIENTID', '1234');
define('YUBIAUTH_APIKEY', 'apikeyfromyubico');  // https://upgrade.yubico.com/getapikey');
```

## Options

Optionally, configure your own URL endpoint in your YML file:
```
YubikeyAuthenticator:
    AuthURL: 'https://my-auth-url.com'
```

### Note of caution

If you use your own Yubikey Authentication server, any One Time Password sent to that will _not_ be invalid on the public Yubico API's

To disable the existing MemberAuthenticator, add the following to your `_config.php`:
```
Authenticator::unregister_authenticator('MemberAuthenticator');
```
This is _not_ a good idea to do on a dev environment ;)

# Configuration

The amount of days, or total amount of logins without Yubikey, are set in the config.yml. You can override it in your mysite config with the following setting:
```
Firesphere\YubiAuth\YubikeyAuthenticator:
  MaxNoYubiLogin: 25
  MaxNoYubiLoginDays: 5
```

# Requirements:

* SilverStripe CMS 3.2 or higher
* SilverStripe Framework 3.2 or higher
* `enygma/yubikey` master

## Test your yubikey

https://demo.yubico.com/

# Actual license

This module is published under BSD 3-clause license, although these are not in the actual classes, the license does apply:

http://www.opensource.org/licenses/BSD-2-Clause

Copyright (c) 2012-NOW(), Simon "Sphere" Erkelens

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# Did you read this entire readme? You rock!

Pictured below is a cow, just for you.
```

               /( ,,,,, )\
              _\,;;;;;;;,/_
           .-"; ;;;;;;;;; ;"-.
           '.__/`_ / \ _`\__.'
              | (')| |(') |
              | .--' '--. |
              |/ o     o \|
              |           |
             / \ _..=.._ / \
            /:. '._____.'   \
           ;::'    / \      .;
           |     _|_ _|_   ::|
         .-|     '==o=='    '|-.
        /  |  . /       \    |  \
        |  | ::|         |   | .|
        |  (  ')         (.  )::|
        |: |   |;  U U  ;|:: | `|
        |' |   | \ U U / |'  |  |
        ##V|   |_/`"""`\_|   |V##
           ##V##         ##V##
```
