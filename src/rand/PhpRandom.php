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

use Exception;
use RuntimeException;

/**
 * Class PhpRandom.
 */
class PhpRandom implements Random
{
    /**
     * @param int $bytes
     *
     * @return string
     */
    public function read(int $bytes): string
    {
        try {
            return random_bytes($bytes);
        } catch (Exception $e) {
            throw new RuntimeException('Not enough entropy');
        }
    }
}
