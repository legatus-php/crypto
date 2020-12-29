<?php
declare(strict_types=1);

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