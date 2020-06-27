<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Token;

/**
 * Interface TokenManager.
 */
interface TokenManager
{
    /**
     * Encodes a payload into a token.
     *
     * @param string $payload
     *
     * @return string
     */
    public function encode(string $payload): string;

    /**
     * Decodes a token into a payload.
     *
     * @param string   $token
     * @param int|null $ttl   Optional ttl for the token
     *
     * @return string
     *
     * @throws TokenDecodingException if there is an error decoding the token
     */
    public function decode(string $token, int $ttl = null): string;
}
