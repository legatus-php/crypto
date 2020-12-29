Legatus Crypto
========================

Simple and secure cryptographic implementations for common tasks

[![Type Coverage](https://shepherd.dev/github/legatus-php/crypto/coverage.svg)](https://shepherd.dev/github/legatus-php/crypto)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Flegatus-php%2Fcrypto%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/legatus-php/crypto/master)

## Installation
You can install the Crypto component using [Composer][composer]:

```bash
composer require legatus/crypto
```

## Quick Start

```php
<?php

use Legatus\Support\LegatusCipher;
use Legatus\Support\SodiumKey;

$secret = SodiumKey::generate()->getBytes();
$cipher = new LegatusCipher($secret);

$encrypted = $cipher->encrypt('message');

// You can optionally pass a ttl for verification
try {
    $message = $cipher->decrypt($encrypted, 3600);
    echo $message; // Writes: "message"
} catch (Legatus\Support\ExpiredCipher $e) {
    // The encrypted message has passed the ttl
} catch (Legatus\Support\InvalidCipher $e) {
    // The encrypted message is invalid
}
```

For more details you can check the [online documentation here][docs].

# Project status & release process

While this library is still under development, it is well tested and should be stable enough to use in production environments.

The current releases are numbered 0.x.y. When a non-breaking change is introduced (adding new methods, optimizing existing code, etc.), y is incremented.

When a breaking change is introduced, a new 0.x version cycle is always started.

It is therefore safe to lock your project to a given release cycle, such as 0.2.*.

If you need to upgrade to a newer release cycle, check the [release history][releases] for a list of changes introduced by each further 0.x.0 version.

## Community
We still do not have a community channel. If you would like to help with that, you can let me know!

## Contributing
Read the contributing guide to know how can you contribute to Legatus.

## Security Issues
Please report security issues privately by email and give us a period of grace before disclosing.

## About Legatus
Legatus is a personal open source project led by Matías Navarro Carter and developed by contributors.

[composer]: https://getcomposer.org/
[docs]: https://legatus.dev/components/crypto
[releases]: https://github.com/legatus-php/crypto/releases