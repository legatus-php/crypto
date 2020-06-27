<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Tests;

use JsonException;
use Legatus\Support\Crypto\Key\FernetV1Key;
use Legatus\Support\Crypto\Tests\Clock\DeterministicClock;
use Legatus\Support\Crypto\Tests\Random\DeterministicRandomBytes;
use Legatus\Support\Crypto\Token\FernetV1TokenManager;
use Legatus\Support\Crypto\Token\TokenDecodingException;
use PHPUnit\Framework\TestCase;

/**
 * Class FernetSpecAcceptanceTest.
 */
class FernetSpecAcceptanceTest extends TestCase
{
    /**
     * @dataProvider getVerifyCases()
     *
     * @param string $token
     * @param string $now
     * @param int    $ttl
     * @param string $src
     * @param string $secret
     */
    public function testItCompliesWithVerifyAcceptanceTests(string $token, string $now, int $ttl, string $src, string $secret): void
    {
        $clock = DeterministicClock::parse($now);
        $manager = new FernetV1TokenManager(FernetV1Key::fromUrlSafeBase64($secret), null, $clock);
        $decoded = $manager->decode($token, $ttl);
        $this->assertSame($src, $decoded);
    }

    /**
     * @dataProvider getInvalidCases()
     *
     * @param string $token
     * @param string $now
     * @param int    $ttl
     * @param string $secret
     */
    public function testItCompliesWithInvalidAcceptanceTests(string $token, string $now, int $ttl, string $secret): void
    {
        $clock = DeterministicClock::parse($now);
        $manager = new FernetV1TokenManager(FernetV1Key::fromUrlSafeBase64($secret), null, $clock);
        $this->expectException(TokenDecodingException::class);
        $manager->decode($token, $ttl);
    }

    /**
     * @dataProvider getGenerateCases()
     *
     * @param string $token
     * @param string $now
     * @param array  $iv
     * @param string $src
     * @param string $secret
     */
    public function testItCompliesWithGenerateAcceptanceTests(string $token, string $now, array $iv, string $src, string $secret): void
    {
        $clock = DeterministicClock::parse($now);
        $randomBytes = DeterministicRandomBytes::fromArray($iv);
        $manager = new FernetV1TokenManager(FernetV1Key::fromUrlSafeBase64($secret), $randomBytes, $clock);
        $generated = $manager->encode($src);
        $this->assertSame($token, $generated);
    }

    /**
     * @return array
     *
     * @throws JsonException
     */
    public function getVerifyCases(): array
    {
        return $this->readJson('verify.json');
    }

    /**
     * @return array
     *
     * @throws JsonException
     */
    public function getGenerateCases(): array
    {
        return $this->readJson('generate.json');
    }

    /**
     * @return array
     *
     * @throws JsonException
     */
    public function getInvalidCases(): array
    {
        $array = [];
        foreach ($this->readJson('invalid.json') as $dataset) {
            $name = array_shift($dataset);
            $array[$name] = $dataset;
        }

        return $array;
    }

    /**
     * @param string $path
     *
     * @return array
     *
     * @throws JsonException
     */
    protected function readJson(string $path): array
    {
        return json_decode(file_get_contents(__DIR__.'/'.$path), true, 512, JSON_THROW_ON_ERROR);
    }
}
