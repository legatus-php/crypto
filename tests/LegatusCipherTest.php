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

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use PHPUnit\Framework\TestCase;

class LegatusCipherTest extends TestCase
{
    public function testItEncryptsCorrectly(): void
    {
        $random = FixedRandom::ofLength(32);
        $key = SodiumKey::generate($random);
        $date = DateTimeImmutable::createFromFormat(DATE_ATOM, '1988-05-04T00:00:00+00:00');
        $clock = new FrozenClock($date);

        $cipher = new LegatusCipher($key, $random, $clock);
        $encrypted = $cipher->encrypt('hello');
        self::assertSame('AAAAACJ-XwAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhdmmCdbOOy43xRVCdmgmwIQNppUI6hEsM0yN_gWMsiwg61-Z7P7Cz4meRLeTN8G4C3oIMM90Q', $encrypted);
    }

    public function testItDecryptsCorrectly(): void
    {
        $random = FixedRandom::ofLength(32);
        $key = SodiumKey::generate($random);
        $date = DateTimeImmutable::createFromFormat(DATE_ATOM, '1988-05-04T00:00:10+00:00');
        $clock = new FrozenClock($date);

        $cipher = new LegatusCipher($key, $random, $clock);
        $message = $cipher->decrypt('AAAAACJ-XwAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhdmmCdbOOy43xRVCdmgmwIQNppUI6hEsM0yN_gWMsiwg61-Z7P7Cz4meRLeTN8G4C3oIMM90Q');
        self::assertSame('hello', $message);
    }

    public function testItDetectsExpiredTokens(): void
    {
        $random = FixedRandom::ofLength(32);
        $key = SodiumKey::generate($random);
        $date = DateTimeImmutable::createFromFormat(DATE_ATOM, '1988-05-04T00:00:10+00:00');
        $clock = new FrozenClock($date);

        $cipher = new LegatusCipher($key, $random, $clock);
        $this->expectException(ExpiredCipher::class);
        $cipher->decrypt('AAAAACJ-XwAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhdmmCdbOOy43xRVCdmgmwIQNppUI6hEsM0yN_gWMsiwg61-Z7P7Cz4meRLeTN8G4C3oIMM90Q', 5);
    }

    public function testItEncryptsWithRotatedKeys(): void
    {
        $random = FixedRandom::ofLength(32);
        $date = DateTimeImmutable::createFromFormat(DATE_ATOM, '1988-05-04T00:00:10+00:00');
        $clock = new FrozenClock($date);

        $old1 = SodiumKey::fromUrlEncodedBase64String('JVmXWgdVfHGibfWjLqXmt4mgrfCIZP04JR311W97ogg');
        $old2 = SodiumKey::fromUrlEncodedBase64String('2nNv5fbOQoDAntzqyaO0D9NtSstnvBJnsSbFY8d3Vn8');
        $current = SodiumKey::fromUrlEncodedBase64String('p396QO7KWi1itoWe1ycKQc3qf9H9G0fA47L4q5rjyPA');
        $rotated = new RotatedKeys($old1, $old2, $current);

        $cipher = new LegatusCipher($rotated, $random, $clock);
        self::assertSame('AAAAACJ-XwoAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhd8Xp7-3x5ZyL5QLSibtO0Nu4xYp9JK2JI7UKS1-r3JQwT6i1KW5eJYnmKNrsnN5wTIeUV1Gw', $cipher->encrypt('hello'));
    }

    public function testItDecryptsWithRotatedKeys(): void
    {
        $random = FixedRandom::ofLength(32);
        $date = DateTimeImmutable::createFromFormat(DATE_ATOM, '1988-05-04T00:00:10+00:00');
        $clock = new FrozenClock($date);

        $old1 = SodiumKey::fromUrlEncodedBase64String('JVmXWgdVfHGibfWjLqXmt4mgrfCIZP04JR311W97ogg');
        $old2 = SodiumKey::fromUrlEncodedBase64String('2nNv5fbOQoDAntzqyaO0D9NtSstnvBJnsSbFY8d3Vn8');
        $current = SodiumKey::fromUrlEncodedBase64String('p396QO7KWi1itoWe1ycKQc3qf9H9G0fA47L4q5rjyPA');
        $rotated = new RotatedKeys($old1, $old2, $current);

        $cipher = new LegatusCipher($rotated, $random, $clock);
        $encrypted = 'AAAAACJ-XwoAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhc0zNZg9Xzg9EWd3sntkaBKRObHFGNpMCRBKMjFqqZnWxsqgrqkC04CuMAq2b6kmLI82e0O2A'; // This was encrypted with old1
        self::assertSame('hello', $cipher->decrypt($encrypted));
    }
}
