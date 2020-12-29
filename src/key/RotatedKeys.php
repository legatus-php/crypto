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

/**
 * Class RotatedKeys.
 */
final class RotatedKeys implements SecretKey
{
    /**
     * @var SecretKey[]
     */
    private array $keys;

    /**
     * RotatedKeys constructor.
     *
     * @param SecretKey ...$keys
     */
    public function __construct(SecretKey ...$keys)
    {
        $this->keys = $keys;
    }

    /**
     * @param SecretKey $key
     */
    public function push(SecretKey $key): void
    {
        $this->keys[] = $key;
    }

    /**
     * @return SecretKey
     */
    public function getCurrentKey(): SecretKey
    {
        $count = count($this->keys);
        if ($count === 0) {
            throw new \RuntimeException('There are no keys present');
        }

        return $this->keys[$count - 1];
    }

    /**
     * @return SecretKey[]
     */
    public function getAllKeys(): array
    {
        return array_reverse($this->keys);
    }

    /**
     * @param string $message
     * @param string $nonce
     *
     * @return string
     */
    public function encrypt(string $message, string $nonce): string
    {
        return $this->getCurrentKey()->encrypt($message, $nonce);
    }

    /**
     * @param string $message
     *
     * @return string
     */
    public function authenticate(string $message): string
    {
        return $this->getCurrentKey()->authenticate($message);
    }

    /**
     * @param string $authenticatedMessage
     *
     * @return string
     */
    public function verify(string $authenticatedMessage): string
    {
        foreach ($this->getAllKeys() as $key) {
            try {
                return $key->verify($authenticatedMessage);
            } catch (InvalidArgumentException $e) {
                continue;
            }
        }
        throw new InvalidArgumentException('Could not verify message');
    }

    /**
     * @param string $cipher
     * @param string $nonce
     *
     * @return string
     */
    public function decrypt(string $cipher, string $nonce): string
    {
        foreach ($this->getAllKeys() as $key) {
            try {
                return $key->decrypt($cipher, $nonce);
            } catch (InvalidArgumentException $e) {
                continue;
            }
        }
        throw new InvalidArgumentException('Could not decrypt message');
    }
}
