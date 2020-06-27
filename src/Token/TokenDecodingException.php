<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Token;

use InvalidArgumentException;
use Throwable;

/**
 * Class TokenDecodingException.
 */
class TokenDecodingException extends InvalidArgumentException
{
    public static function invalidEncoding(Throwable $previous = null): TokenDecodingException
    {
        return new self('Invalid encoding for token', 1, $previous);
    }

    public static function tokenTooShort(): TokenDecodingException
    {
        return new self('The provided token is too short', 2);
    }

    public static function unsupportedVersion(): TokenDecodingException
    {
        return new self('Unsupported token version', 3);
    }

    /**
     * @return TokenDecodingException
     */
    public static function expiredToken(): TokenDecodingException
    {
        return new self('The token has expired', 4);
    }

    /**
     * @return TokenDecodingException
     */
    public static function farFuture(): TokenDecodingException
    {
        return new self('The token time is too far in the future', 5);
    }

    /**
     * @return TokenDecodingException
     */
    public static function incorrectHmac(): TokenDecodingException
    {
        return new self('The hmac signature is invalid', 6);
    }

    /**
     * @return TokenDecodingException
     */
    public static function wrongPadding(): TokenDecodingException
    {
        return new self('Wrong padding', 7);
    }

    public static function invalidPayloadSize(): TokenDecodingException
    {
        return new self('Payload size is not multiple of block size', 8);
    }

    /**
     * TokenDecodingException constructor.
     *
     * @param string         $message
     * @param int            $code
     * @param Throwable|null $previous
     */
    public function __construct(string $message, int $code, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
