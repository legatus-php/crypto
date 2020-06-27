<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Key;

use Legatus\Support\Crypto\Encoding\EncodingException;
use Legatus\Support\Crypto\Encoding\UrlSafeBase64;
use Legatus\Support\Crypto\Random\PhpRandomBytes;
use Legatus\Support\Crypto\Random\RandomBytes;
use UnexpectedValueException;

/**
 * Class FernetV1Key.
 *
 * A Fernet V1 Key consists of 252 bits encoded in url safe base 64. The first
 * 128 bits are used for signing, and the next 128 bits are used for encryption.
 *
 * @see https://github.com/fernet/spec/blob/master/Spec.md#key-format
 */
final class FernetV1Key implements Key
{
    private const ENCRYPT_METHOD = 'aes-128-cbc';
    private const ENCRYPT_FLAGS = OPENSSL_ZERO_PADDING + OPENSSL_RAW_DATA;

    private string $signingKey;
    private string $encryptionKey;

    /**
     * @param string $key
     *
     * @return FernetV1Key
     *
     * @throws KeyException
     */
    public static function fromUrlSafeBase64(string $key): FernetV1Key
    {
        try {
            $bytes = UrlSafeBase64::decode($key);
        } catch (EncodingException $e) {
            throw KeyException::invalidKeyEncoding($e);
        }
        if (strlen($bytes) !== 32) {
            throw KeyException::invalidKeyLength();
        }
        [$signingKey, $encryptionKey] = str_split($bytes, 16);

        return new self($signingKey, $encryptionKey);
    }

    /**
     * @param RandomBytes|null $randomBytes
     *
     * @return FernetV1Key
     */
    public static function generate(RandomBytes $randomBytes = null): FernetV1Key
    {
        $randomBytes = $randomBytes ?? new PhpRandomBytes();

        return new self(
            $randomBytes->generate(16),
            $randomBytes->generate(16),
        );
    }

    /**
     * FernetV1Key constructor.
     *
     * @param string $signingKey
     * @param string $encryptionKey
     */
    private function __construct(string $signingKey, string $encryptionKey)
    {
        $this->signingKey = $signingKey;
        $this->encryptionKey = $encryptionKey;
    }

    /**
     * @param string $payload
     *
     * @return string
     */
    public function sign(string $payload): string
    {
        return hash_hmac('sha256', $payload, $this->signingKey, true);
    }

    /**
     * @param string $payload
     * @param string $iv
     *
     * @return string
     */
    public function encrypt(string $payload, string $iv = ''): string
    {
        if (strlen($iv) !== 16) {
            throw new UnexpectedValueException('IV must be present and of 16 bytes');
        }

        $cipher = openssl_encrypt($payload, self::ENCRYPT_METHOD, $this->encryptionKey, self::ENCRYPT_FLAGS, $iv);
        if ($cipher === false) {
            throw new UnexpectedValueException('Message length must be a multiple of 16 bytes');
        }

        return $cipher;
    }

    /**
     * @param string $payload
     * @param string $iv
     *
     * @return string
     */
    public function decrypt(string $payload, string $iv = ''): string
    {
        if (strlen($iv) !== 16) {
            throw new UnexpectedValueException('IV must be present and of 16 bytes');
        }

        $decrypted = openssl_decrypt($payload, self::ENCRYPT_METHOD, $this->encryptionKey, self::ENCRYPT_FLAGS, $iv);
        if ($decrypted === false) {
            throw new UnexpectedValueException('Invalid decryption');
        }

        return $decrypted;
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        return UrlSafeBase64::encode($this->signingKey.$this->encryptionKey);
    }
}
