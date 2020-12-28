<?php

declare(strict_types=1);

/*
 * @project Legatus Crypto
 * @link https://github.com/legatus-php/crypto
 * @package legatus/crypto
 * @author Matias Navarro-Carter mnavarrocarter@gmail.com
 * @license MIT
 * @copyright 2021 Matias Navarro-Carter
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support;

use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;
use SodiumException;

/**
 * Class LegatusCipher.
 */
final class LegatusCipher implements Cipher
{
    private const VERSION = "\x64";
    private const MAX_CLOCK_SKEW = 60;
    private const MIN_LENGTH = 49;

    private string $key;
    private Clock $clock;
    private Random $random;

    /**
     * LegatusCipher constructor.
     *
     * @param string      $key
     * @param Random|null $random
     * @param Clock|null  $clock
     */
    public function __construct(string $key, Random $random = null, Clock $clock = null)
    {
        $this->key = $key;
        $this->clock = $clock ?? new SystemClock();
        $this->random = $random ?? new PhpRandom();
    }

    /**
     * @param string $plainText
     *
     * @return string
     *
     * @throws SodiumException
     */
    public function encrypt(string $plainText): string
    {
        $time = $this->getUInt64Time();
        $nonce = $this->random->read(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($plainText, $nonce, $this->key);

        return sodium_bin2base64(self::VERSION.$time.$nonce.$cipher, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * @param string   $encrypted
     * @param int|null $ttl
     *
     * @return string
     *
     * @throws InvalidCipher
     * @throws SodiumException
     * @throws ExpiredCipher
     */
    public function decrypt(string $encrypted, int $ttl = null): string
    {
        try {
            $decoded = sodium_base642bin($encrypted, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (SodiumException $e) {
            throw new InvalidCipher('Invalid base64 encoding');
        }

        $length = strlen($decoded);
        if ($length < self::MIN_LENGTH) {
            throw new InvalidCipher('Cipher too short');
        }

        $version = $decoded[0];
        $time = substr($decoded, 1, 8);
        $nonce = substr($decoded, 9, SODIUM_CRYPTO_BOX_NONCEBYTES);
        $cipher = substr($decoded, 9 + SODIUM_CRYPTO_BOX_NONCEBYTES);

        // We ensure the first byte is 0xa0
        if ($version !== self::VERSION) {
            throw new InvalidCipher('Incorrect version');
        }

        // We extract the time and do future and expiration checks
        $now = $this->clock->now()->getTimestamp();
        $messageTime = $this->getTimestamp($time);
        $timeDiff = $now - $messageTime;

        if ($ttl > 0 && $timeDiff > $ttl) {
            throw new ExpiredCipher();
        }

        if ($messageTime > ($now + self::MAX_CLOCK_SKEW)) {
            throw new InvalidCipher('Too far in the future');
        }

        $plain = sodium_crypto_secretbox_open($cipher, $nonce, $this->key);
        if ($plain === false) {
            throw new InvalidCipher('Bad ciphertext');
        }

        return $plain;
    }

    /**
     * @return string
     */
    private function getUInt64Time(): string
    {
        return pack('J', $this->clock->now()->getTimestamp());
    }

    private function getTimestamp(string $uInt64): int
    {
        return unpack('J', $uInt64)[1];
    }
}
