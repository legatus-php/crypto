<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Cipher;

/**
 * Interface Cipher.
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
     * @param string   $cipher
     * @param int|null $ttl
     *
     * @throws InvalidCipher
     * @throws ExpiredCipher
     *
     * @return string
     */
    public function decrypt(string $cipher, int $ttl = null): string;
}
