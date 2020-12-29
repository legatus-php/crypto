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

/**
 * Class CipherStatefulTokenTest.
 */
class CipherStatefulTokenTest extends TestCase
{
    public function testItEncodesToken(): void
    {
        $key = SodiumKey::generate();

        $cipher = new LegatusCipher($key);
        $token = new CipherStatefulToken($cipher);

        $tok = $token->encode([
            'id' => '252332532523',
            'name' => 'Matias Navarro Carter',
        ], 'at');

        self::assertSame([
            'id' => '252332532523',
            'name' => 'Matias Navarro Carter',
        ], $token->decode($tok, 'at'));
    }
}
