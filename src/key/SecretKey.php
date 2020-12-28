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

use SodiumException;

/**
 * The SecretKey class provides helpers to create secret keys needed by the
 * LegatusCipher.
 */
class SecretKey
{
    private string $bytes;

    /**
     * @param string $filename
     *
     * @return SecretKey
     *
     * @throws SodiumException
     */
    public static function persistent(string $filename): SecretKey
    {
        if (!is_file($filename)) {
            $key = static::generate();
            file_put_contents($filename, $key->toString());
        }

        return static::fromUrlEncodedBase64String(file_get_contents($filename));
    }

    /**
     * @param string $base64
     *
     * @return SecretKey
     *
     * @throws SodiumException
     */
    public static function fromUrlEncodedBase64String(string $base64): SecretKey
    {
        return new self(sodium_base642bin($base64, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));
    }

    /**
     * @param Random|null $random
     *
     * @return SecretKey
     */
    public static function generate(Random $random = null): SecretKey
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
     * @param string $cipher
     * @param string $nonce
     *
     * @return string
     *
     * @throws InvalidCipher
     * @throws SodiumException
     */
    public function decrypt(string $cipher, string $nonce): string
    {
        $result = sodium_crypto_secretbox_open($cipher, $nonce, $this->bytes);
        if ($result === false) {
            throw new InvalidCipher('Invalid cipher');
        }

        return $result;
    }

    private function guard(): void
    {
        if (strlen($this->bytes) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \RuntimeException(sprintf('The key length must be %s bytes in size', SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
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
     *
     * @throws SodiumException
     */
    public function toString(): string
    {
        return sodium_bin2base64($this->bytes, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
