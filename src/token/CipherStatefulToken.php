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

use JsonException;

/**
 * Class CipherStatefulToken.
 */
class CipherStatefulToken implements StatefulToken
{
    /**
     * @var Cipher
     */
    private Cipher $cipher;

    /**
     * CipherStatefulToken constructor.
     *
     * @param Cipher $cipher
     */
    public function __construct(Cipher $cipher)
    {
        $this->cipher = $cipher;
    }

    /**
     * @param array  $data
     * @param string $prefix
     *
     * @return string
     *
     * @throws JsonException
     */
    public function encode(array $data, string $prefix = ''): string
    {
        $message = json_encode($data, JSON_THROW_ON_ERROR);
        $encrypted = $this->cipher->encrypt($message);
        if ($prefix !== '') {
            $encrypted = $prefix.'_'.$encrypted;
        }

        return $encrypted;
    }

    /**
     * @param string   $token
     * @param string   $prefix
     * @param int|null $ttl
     *
     * @return array
     *
     * @throws ExpiredCipher
     * @throws InvalidCipher
     * @throws JsonException
     */
    public function decode(string $token, string $prefix = '', int $ttl = null): array
    {
        if ($prefix !== '' && strpos($token, $prefix.'_') !== 0) {
            throw new \RuntimeException('Invalid token');
        }
        $encrypted = substr($token, strlen($prefix) + 1);
        $decrypted = $this->cipher->decrypt($encrypted, $ttl);

        return json_decode($decrypted, true, 512, JSON_THROW_ON_ERROR);
    }
}
