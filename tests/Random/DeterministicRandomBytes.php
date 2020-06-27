<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Tests\Random;

use Legatus\Support\Crypto\Random\RandomBytes;
use RuntimeException;

/**
 * Class DeterministicRandomBytes.
 */
final class DeterministicRandomBytes implements RandomBytes
{
    private string $bytes;

    /**
     * @param array $array
     *
     * @return RandomBytes
     */
    public static function fromArray(array $array): RandomBytes
    {
        return new self(implode(array_map('chr', $array)));
    }

    /**
     * DeterministicRandomBytes constructor.
     *
     * @param string $bytes
     */
    public function __construct(string $bytes)
    {
        $this->bytes = $bytes;
    }

    public function generate(int $length): string
    {
        if ($length !== strlen($this->bytes)) {
            throw new RuntimeException('The requested bytes length is not the length of the internal bytes');
        }

        return $this->bytes;
    }
}
