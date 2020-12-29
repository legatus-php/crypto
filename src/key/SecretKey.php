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
 * Interface SecretKey.
 */
interface SecretKey
{
    /**
     * Encrypts a message.
     *
     * Implementors SHOULD use authenticated encryption under the hood.
     *
     * The output of the encryption process MUST NOT be encoded in any way.
     *
     * @param string $message
     * @param string $nonce
     *
     * @return string The raw bytes
     */
    public function encrypt(string $message, string $nonce): string;

    /**
     * Decrypts a message.
     *
     * Implementors MUST assume both the cipher and the nonce are unencoded raw
     * bytes.
     *
     * @param string $cipher
     * @param string $nonce
     *
     * @return string
     *
     * @throws InvalidArgumentException when the cipher could not be decrypted or
     *                                  was invalid
     */
    public function decrypt(string $cipher, string $nonce): string;

    /**
     * @param string $message
     *
     * @return string The authenticated message
     */
    public function authenticate(string $message): string;

    /**
     * Verifies an authenticated message.
     *
     * @param string $authenticatedMessage
     *
     * @return string The message without authentication
     *
     * @throws InvalidArgumentException when the message is not valid
     */
    public function verify(string $authenticatedMessage): string;
}
