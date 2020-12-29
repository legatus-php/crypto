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
use RuntimeException;
use SodiumException;

/**
 * The SodiumKey class provides helpers to create secret keys needed by the
 * LegatusCipher.
 */
class SodiumKey implements SecretKey
{
    private string $bytes;

    /**
     * Creates Sodium Keys from a file.
     *
     * The keys MUST be separated by a new line character ("\n").
     *
     * The keys MUST be encoded in url safe base 64, with no padding.
     *
     * The last key in the file is always the key used for encryption
     * For decryption, the keys are tested from bottom to to top.
     *
     * If the file does not exist, then it is automatically created and a
     * single random key is generated.
     *
     * @param string      $filename
     * @param Random|null $random
     *
     * @return RotatedKeys
     */
    public static function fromFile(string $filename, Random $random = null): RotatedKeys
    {
        if (!is_file($filename)) {
            $dir = dirname($filename);
            if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
                throw new RuntimeException("Could not create directory \"$dir\"");
            }
            $key = static::generate($random);
            file_put_contents($filename, $key->toString().PHP_EOL);
        }

        $keys = new RotatedKeys();
        $handle = fopen($filename, 'rb');

        while (!feof($handle)) {
            $line = fgets($handle);
            if (!is_string($line)) {
                continue;
            }
            $line = rtrim($line, PHP_EOL);
            if ($line === '') {
                continue;
            }
            $keys->push(static::fromUrlEncodedBase64String($line));
        }

        return $keys;
    }

    /**
     * @param string $base64
     *
     * @return SodiumKey
     */
    public static function fromUrlEncodedBase64String(string $base64): SodiumKey
    {
        return new self(Base64\url_decode($base64));
    }

    /**
     * @param Random|null $random
     *
     * @return SodiumKey
     */
    public static function generate(Random $random = null): SodiumKey
    {
        $random = $random ?? new PhpRandom();

        return new self($random->read(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
    }

    /**
     * LegatusKey constructor.
     *
     * @param string $bytes
     */
    public function __construct(string $bytes)
    {
        $this->bytes = $bytes;
        $this->guard();
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $cipher, string $nonce): string
    {
        $key = $this->bytes;
        try {
            $result = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        } catch (SodiumException $e) {
            throw new InvalidArgumentException('Failed to decrypt data: '.$e->getMessage(), 0, $e);
        }
        if ($result === false) {
            throw new InvalidArgumentException('Failed to decrypt data');
        }

        return $result;
    }

    /**
     * @param string $message
     * @param string $nonce
     *
     * @return string
     */
    public function encrypt(string $message, string $nonce): string
    {
        $key = $this->bytes;
        try {
            return sodium_crypto_secretbox($message, $nonce, $key);
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not encrypt message: '.$e->getMessage(), 0, $e);
        }
    }

    /**
     * @param string $message
     *
     * @return string
     */
    public function authenticate(string $message): string
    {
        return $message.$this->hash($message);
    }

    /**
     * @param string $message
     *
     * @return string
     */
    protected function hash(string $message): string
    {
        try {
            $auth = sodium_crypto_auth($message, $this->bytes);
        } catch (SodiumException $e) {
            throw new RuntimeException('Could not authenticate message');
        }

        return $auth;
    }

    /**
     * @param string $authenticatedMessage
     *
     * @return string
     */
    public function verify(string $authenticatedMessage): string
    {
        $message = substr($authenticatedMessage, 0, SODIUM_CRYPTO_AUTH_BYTES * -1);
        $hash = substr($authenticatedMessage, SODIUM_CRYPTO_AUTH_BYTES * -1);
        $auth = $this->hash($message);
        if (!hash_equals($hash, $auth)) {
            throw new InvalidArgumentException('The authenticated message is invalid');
        }

        return $message;
    }

    /**
     * @return int
     */
    public function getAuthSize(): int
    {
        return SODIUM_CRYPTO_AUTH_BYTES;
    }

    private function guard(): void
    {
        if (strlen($this->bytes) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException(sprintf('The key length must be %s bytes in size', SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
        }
    }

    /**
     * @return string
     */
    public function getBytes(): string
    {
        return $this->bytes;
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        return Base64\url_encode($this->bytes);
    }
}
