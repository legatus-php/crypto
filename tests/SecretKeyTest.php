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

use PHPUnit\Framework\TestCase;
use Vfs\FileSystem;

class SecretKeyTest extends TestCase
{
    public function testItGeneratesASecretKey(): void
    {
        $random = FixedRandom::ofLength(32);
        $key = SecretKey::generate($random)->toString();
        self::assertSame('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', $key);
    }

    public function testItGeneratesAPersistentSecretKey(): void
    {
        $fs = FileSystem::factory('vfs://');
        $fs->mount();

        $random = FixedRandom::ofLength(32);
        $key = SecretKey::persistent('vfs://data/secret.key', $random)->toString();
        self::assertSame('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', $key);
        self::assertFileExists('vfs://data/secret.key');

        $fs->unmount();
    }
}
