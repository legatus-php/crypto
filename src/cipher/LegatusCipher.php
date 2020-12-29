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

use InvalidArgumentException;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;

/**
 * Class LegatusCipher.
 */
final class LegatusCipher implements Cipher
{
    private const MAX_CLOCK_SKEW = 60;
    private const MIN_LENGTH = 48;
    private const NONCE_LENGTH = 24;

    private SecretKey $key;
    private Clock $clock;
    private Random $random;

    /**
     * LegatusCipher constructor.
     *
     * @param SecretKey   $key
     * @param Random|null $random
     * @param Clock|null  $clock
     #*/
    public function __construct(SecretKey $key, Random $random = null, Clock $clock = null)
    {
        $this->key = $key;
        $this->clock = $clock ?? new SystemClock();
        $this->random = $random ?? new PhpRandom();
    }

    /**
     * @param string $plainText
     *
     * @return string
     */
    public function encrypt(string $plainText): string
    {
        $time = $this->getUInt64Time();
        $nonce = $this->random->read(self::NONCE_LENGTH);
        $cipher = $this->key->encrypt($plainText, $nonce);

        return Base64\url_encode($this->key->authenticate($time.$nonce.$cipher));
    }

    /**
     * @param string   $encrypted
     * @param int|null $ttl
     *
     * @return string
     *
     * @throws InvalidCipher
     * @throws ExpiredCipher
     */
    public function decrypt(string $encrypted, int $ttl = null): string
    {
        try {
            $decoded = Base64\url_decode($encrypted);
        } catch (InvalidArgumentException $e) {
            throw new InvalidCipher('Invalid base64 encoding');
        }

        $length = strlen($decoded);
        if ($length < self::MIN_LENGTH) {
            throw new InvalidCipher('Cipher too short');
        }

        try {
            $base = $this->key->verify($decoded);
        } catch (InvalidArgumentException $e) {
            throw new InvalidCipher('The message has been modified');
        }

        $time = substr($base, 0, 8);
        $nonce = substr($base, 8, self::NONCE_LENGTH);
        $cipher = substr($base, 8 + self::NONCE_LENGTH);

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

        try {
            $plain = $this->key->decrypt($cipher, $nonce);
        } catch (InvalidArgumentException $e) {
            throw new InvalidCipher('Decryption error: '.$e->getMessage(), $e);
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
