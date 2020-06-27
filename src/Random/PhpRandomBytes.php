<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Random;

use RuntimeException;

/**
 * Class PhpRandomBytes.
 */
class PhpRandomBytes implements RandomBytes
{
    /**
     * @param int $length
     *
     * @return string
     */
    public function generate(int $length): string
    {
        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            throw new RuntimeException('Not enough entropy');
        }
    }
}
