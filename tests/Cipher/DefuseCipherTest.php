<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Tests\Cipher;

use Defuse\Crypto\Key;
use Lcobucci\Clock\FrozenClock;
use Legatus\Support\Crypto\Cipher\DefuseCipher;
use Legatus\Support\Crypto\Cipher\ExpiredCipher;
use Legatus\Support\Crypto\Cipher\InvalidCipher;
use PHPUnit\Framework\TestCase;

/**
 * Class DefuseCipherTest.
 */
class DefuseCipherTest extends TestCase
{
    public function testItEncryptsAndDecrypts(): void
    {
        $key = Key::createNewRandomKey();
        $cipher = new DefuseCipher($key);

        $encrypted = $cipher->encrypt('hello');

        $message = $cipher->decrypt($encrypted, 3600);
        self::assertSame('hello', $message);
    }

    public function testItDetectsExpiredCiphers(): void
    {
        $clock = new FrozenClock(new \DateTimeImmutable('now'));

        $key = Key::createNewRandomKey();
        $cipher = new DefuseCipher($key, $clock);
        $encrypted = $cipher->encrypt('hello');

        $clock->setTo(new \DateTimeImmutable('+1 week'));
        $this->expectException(ExpiredCipher::class);
        $cipher->decrypt($encrypted, 3600);
    }

    /**
     * @throws ExpiredCipher
     * @throws InvalidCipher
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    public function testItCatchesInvalidCipher(): void
    {
        $key = Key::createNewRandomKey();
        $cipher = new DefuseCipher($key);
        $this->expectException(InvalidCipher::class);
        $cipher->decrypt('totally-wrong-cipher', 3600);
    }
}
