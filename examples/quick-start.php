<?php
declare(strict_types=1);

$key = Defuse\Crypto\Key::createNewRandomKey();
$cipher = new Legatus\Support\DefuseCipher($key);

$encrypted = $cipher->encrypt('message');

// You can optionally pass a ttl for verification
try {
    $message = $cipher->decrypt($encrypted, 3600);
} catch (Defuse\Crypto\Exception\EnvironmentIsBrokenException $e) {
    // There is no access to a CPRNG
} catch (Legatus\Support\ExpiredCipher $e) {
    // The message has passed the ttl
} catch (Legatus\Support\InvalidCipher $e) {
    // The message is invalid
}