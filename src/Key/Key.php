<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Key;

/**
 * Interface Key.
 *
 * This is the contract for any kind of cryptographic key that allows encrypting
 * and signing operations.
 *
 * In case of payloads requiring more than one argument (like an IV in the case
 * of the Fernet implementation), these can be prepended to the actual message
 * and then subtracted from the string, since we know the bytes they consume in
 * advance.
 */
interface Key
{
    /**
     * Signs a payload with this key.
     *
     * @param string $payload
     *
     * @return string A raw binary string without special encoding
     */
    public function sign(string $payload): string;

    /**
     * @param string $payload
     *
     * @return string
     */
    public function encrypt(string $payload): string;

    /**
     * @param string $payload
     *
     * @return string
     */
    public function decrypt(string $payload): string;
}
