<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support;

use Exception;
use Throwable;

/**
 * Class InvalidCipher.
 */
class InvalidCipher extends Exception
{
    /**
     * InvalidCipher constructor.
     *
     * @param Throwable|null $previous
     */
    public function __construct(Throwable $previous = null)
    {
        parent::__construct('Invalid cipher', 0, $previous);
    }
}
