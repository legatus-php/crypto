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
 * Class FixedRandom.
 */
final class FixedRandom implements Random
{
    private string $bytes;

    /**
     * @param int $bytes
     *
     * @return FixedRandom
     */
    public static function ofLength(int $bytes): FixedRandom
    {
        return self::fromUint8Array(...range(0, $bytes));
    }

    /**
     * @param int ...$bytes
     *
     * @return FixedRandom
     */
    public static function fromUint8Array(int ...$bytes): FixedRandom
    {
        return new self(implode('', array_map('chr', $bytes)));
    }

    public function __construct(string $bytes)
    {
        $this->bytes = $bytes;
    }

    /**
     * @param int $bytes
     *
     * @return string
     */
    public function read(int $bytes): string
    {
        return substr($this->bytes, 0, $bytes);
    }
}
