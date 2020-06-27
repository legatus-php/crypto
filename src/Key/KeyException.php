<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Key;

use InvalidArgumentException;
use Throwable;

/**
 * Class KeyException.
 */
class KeyException extends InvalidArgumentException
{
    /**
     * @param Throwable|null $previous
     *
     * @return KeyException
     */
    public static function invalidKeyEncoding(Throwable $previous = null): KeyException
    {
        return new self('Invalid key encoding', 1, $previous);
    }

    /**
     * @return KeyException
     */
    public static function invalidKeyLength(): KeyException
    {
        return new self('Invalid key length', 2);
    }

    public function __construct(string $message, int $code, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
