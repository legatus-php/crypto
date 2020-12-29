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

/**
 * A Cipher provides the contract to generate a secure, time based, authenticated
 * and encoded ciphertexts.
 */
interface Cipher
{
    /**
     * @param string $plainText
     *
     * @return string
     */
    public function encrypt(string $plainText): string;

    /**
     * @param string   $encrypted
     * @param int|null $ttl
     *
     * @return string
     *
     * @throws ExpiredCipher|InvalidCipher
     */
    public function decrypt(string $encrypted, int $ttl = null): string;
}
