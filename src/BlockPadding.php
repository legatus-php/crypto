<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto;

use UnexpectedValueException;

/**
 * Class BlockPadding.
 */
class BlockPadding
{
    /**
     * @param string $string
     * @param int    $blockSize
     *
     * @return string
     */
    public static function pad(string $string, int $blockSize = 16): string
    {
        $pad = $blockSize - (strlen($string) % $blockSize);
        $string .= str_repeat(chr($pad), $pad);

        return $string;
    }

    /**
     * @param string $padded
     *
     * @return string
     *
     * @throws UnexpectedValueException when the padding is wrong
     */
    public static function unpad(string $padded): string
    {
        $pad = ord($padded[strlen($padded) - 1]);
        if ($pad !== substr_count(substr($padded, -$pad), chr($pad))) {
            throw new UnexpectedValueException('Wrong padding');
        }

        return substr($padded, 0, -$pad);
    }
}
