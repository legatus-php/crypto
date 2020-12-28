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

use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\TestCase;

class LegatusCipherTest extends TestCase
{
    public function testItEncryptsAndDecrypts(): void
    {
        $key = SecretKey::generate()->getBytes();

        $cipher = new LegatusCipher($key);
        $encrypted = $cipher->encrypt('hello');

        self::assertSame('hello', $cipher->decrypt($encrypted));
    }

    public function testItThrowsErrorOnExpired(): void
    {
        $key = SecretKey::generate()->getBytes();

        $clock = new FrozenClock(new \DateTimeImmutable('now'));
        $cipher = new LegatusCipher($key, null, $clock);
        $encrypted = $cipher->encrypt('hello');

        // Advance time two hours
        $clock->setTo(new \DateTimeImmutable('+2 hours'));

        $this->expectException(ExpiredCipher::class);
        $cipher->decrypt($encrypted, 3600);
    }
}
