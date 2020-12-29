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

namespace Legatus\Support\Base64;

use InvalidArgumentException;
use RuntimeException;
use SodiumException;

/**
 * @param string $message
 *
 * @return string
 *
 * @throws RuntimeException
 */
function url_encode(string $message): string
{
    try {
        return sodium_bin2base64($message, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    } catch (SodiumException $e) {
        throw new RuntimeException('Could not encode message');
    }
}

/**
 * @param string $encoded
 *
 * @return string
 *
 * @throws InvalidArgumentException
 */
function url_decode(string $encoded): string
{
    try {
        return sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    } catch (SodiumException $e) {
        throw new InvalidArgumentException('Invalid base64 encoded string');
    }
}
