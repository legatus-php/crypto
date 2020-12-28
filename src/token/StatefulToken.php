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
 * Interface StatefulToken.
 */
interface StatefulToken
{
    /**
     * Creates a token that contains data.
     *
     * @param array  $data
     * @param string $prefix
     *
     * @return string
     */
    public function encode(array $data, string $prefix = ''): string;

    /**
     * Extracts the data from a token.
     *
     * Optionally, validates time and prefix.
     *
     * @param string   $token
     * @param string   $prefix
     * @param int|null $ttl
     *
     * @return array
     */
    public function decode(string $token, string $prefix = '', int $ttl = null): array;
}
