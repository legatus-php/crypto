<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Token;

use Legatus\Support\Crypto\BlockPadding;
use Legatus\Support\Crypto\Clock\Clock;
use Legatus\Support\Crypto\Clock\SystemClock;
use Legatus\Support\Crypto\Encoding\EncodingException;
use Legatus\Support\Crypto\Encoding\UrlSafeBase64;
use Legatus\Support\Crypto\Key\FernetV1Key;
use Legatus\Support\Crypto\Random\PhpRandomBytes;
use Legatus\Support\Crypto\Random\RandomBytes;
use UnexpectedValueException;

/**
 * Class FernetV1TokenManager.
 *
 * Fernet tokens are much more secure than Json Web Tokens, and can cover the
 * same needs JWTs are used for.
 */
final class FernetV1TokenManager implements TokenManager
{
    private const VERSION = "\x80";
    private const MIN_LENGTH = 73;
    private const MAX_CLOCK_SKEW = 60;

    /**
     * @var FernetV1Key
     */
    private FernetV1Key $key;
    /**
     * @var RandomBytes
     */
    private RandomBytes $randomBytes;
    /**
     * @var Clock
     */
    private Clock $clock;

    /**
     * FernetV1TokenManager constructor.
     *
     * @param FernetV1Key $key
     * @param RandomBytes $randomBytes
     * @param Clock       $clock
     */
    public function __construct(FernetV1Key $key, RandomBytes $randomBytes = null, Clock $clock = null)
    {
        $this->key = $key;
        $this->randomBytes = $randomBytes ?? new PhpRandomBytes();
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * @param string $payload
     *
     * @return string
     */
    public function encode(string $payload): string
    {
        $binTime = $this->packTime($this->clock->now());
        $iv = $this->randomBytes->generate(16);
        $paddedMessage = BlockPadding::pad($payload);
        $cipher = $this->key->encrypt($paddedMessage, $iv);
        $base = self::VERSION.$binTime.$iv.$cipher;
        $hmac = $this->key->sign($base);

        return UrlSafeBase64::encode($base.$hmac);
    }

    /**
     * @param string   $token
     * @param int|null $ttl
     *
     * @return string
     */
    public function decode(string $token, int $ttl = null): string
    {
        try {
            $decoded = UrlSafeBase64::decode($token);
        } catch (EncodingException $e) {
            throw TokenDecodingException::invalidEncoding($e);
        }
        $length = strlen($decoded);
        if ($length < self::MIN_LENGTH) {
            throw TokenDecodingException::tokenTooShort();
        }
        $base = substr($decoded, 0, -32);
        $version = $base[0];
        $tokenTime = $this->unpackTime(substr($base, 1, 8));

        // We ensure the first byte is 0x80
        if ($version !== self::VERSION) {
            throw TokenDecodingException::unsupportedVersion();
        }

        $now = $this->clock->now();
        $timeDiff = $now - $tokenTime;

        if ($ttl > 0 && $timeDiff > $ttl) {
            throw TokenDecodingException::expiredToken();
        }

        if ($tokenTime > ($now + self::MAX_CLOCK_SKEW)) {
            throw TokenDecodingException::farFuture();
        }

        // We recompute the HMAC and ensure matched the token one
        $hmac = substr($decoded, -32);
        $recomputedHmac = $this->key->sign($base);
        if ($hmac !== $recomputedHmac) {
            throw TokenDecodingException::incorrectHmac();
        }

        // Decrypt the cipher with the iv
        $iv = substr($base, 9, 16);
        $cipher = substr($base, 25);
        try {
            $message = $this->key->decrypt($cipher, $iv);
        } catch (UnexpectedValueException $e) {
            throw TokenDecodingException::invalidPayloadSize();
        }

        // Unpad decrypted, returning original message
        try {
            return BlockPadding::unpad($message);
        } catch (UnexpectedValueException $e) {
            throw TokenDecodingException::wrongPadding();
        }
    }

    /**
     * @param int $timestamp
     *
     * @return string
     */
    protected function packTime(int $timestamp): string
    {
        return pack('J', $timestamp);
    }

    /**
     * @param string $binary
     *
     * @return int
     */
    protected function unpackTime(string $binary): int
    {
        return unpack('J', $binary)[1];
    }
}
