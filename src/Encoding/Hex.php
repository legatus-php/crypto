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
 * Class Hex.
 */
final class Hex
{
    /**
     * @param string $bin
     *
     * @return string
     */
    public static function encode(string $bin): string
    {
        return bin2hex($bin);
    }

    /**
     * @param string $hex
     *
     * @return string
     */
    public static function decode(string $hex): string
    {
        return hex2bin($hex);
    }
}
