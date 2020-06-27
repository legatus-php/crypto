<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Encoding;

/**
 * Class UrlSafeBase64.
 */
final class UrlSafeBase64
{
    /**
     * @param string $data
     *
     * @return string
     */
    public static function encode(string $data): string
    {
        return str_replace(['+', '/'], ['-', '_'], base64_encode($data));
    }

    /**
     * @param string $base64
     *
     * @return string
     *
     * @throws EncodingException
     */
    public static function decode(string $base64): string
    {
        $result = base64_decode(str_replace(['-', '_'], ['+', '/'], $base64), true);
        if (!is_string($result)) {
            throw new EncodingException('Invalid base64 string provided');
        }

        return $result;
    }
}
