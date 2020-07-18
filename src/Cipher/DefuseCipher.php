<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Cipher;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;

/**
 * Class DefuseCipher.
 */
final class DefuseCipher implements Cipher
{
    private Key $key;
    private Clock $clock;

    /**
     * DefuseCipher constructor.
     *
     * @param Key        $key
     * @param Clock|null $clock
     */
    public function __construct(Key $key, Clock $clock = null)
    {
        $this->key = $key;
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * @param string $plainText
     *
     * @return string
     *
     * @throws EnvironmentIsBrokenException
     */
    public function encrypt(string $plainText): string
    {
        $base64 = base64_encode($plainText);
        $time = $this->clock->now()->getTimestamp();

        return Crypto::encrypt($base64.'.'.$time, $this->key);
    }

    /**
     * {@inheritdoc}
     *
     * @throws EnvironmentIsBrokenException
     */
    public function decrypt(string $cipher, int $ttl = null): string
    {
        try {
            $message = Crypto::decrypt($cipher, $this->key);
        } catch (WrongKeyOrModifiedCiphertextException $e) {
            throw new InvalidCipher($e);
        }
        [$base64, $time] = explode('.', $message);
        $time = (int) $time;
        $now = $this->clock->now()->getTimestamp();
        if ($ttl !== null && $now > ($time + $ttl)) {
            throw new ExpiredCipher();
        }

        return base64_decode($base64);
    }
}
