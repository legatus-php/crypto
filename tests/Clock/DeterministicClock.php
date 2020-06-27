<?php

declare(strict_types=1);

/*
 * This file is part of the Legatus project organization.
 * (c) Matías Navarro-Carter <contact@mnavarro.dev>
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Legatus\Support\Crypto\Tests\Clock;

use DateTimeImmutable;
use DateTimeInterface;
use Legatus\Support\Crypto\Clock\Clock;

/**
 * Class DeterministicClock.
 */
final class DeterministicClock implements Clock
{
    private DateTimeInterface $dateTime;

    /**
     * @param string $time
     * @param string $format
     *
     * @return Clock
     */
    public static function parse(string $time, string $format = DATE_ATOM): Clock
    {
        return new self(DateTimeImmutable::createFromFormat($format, $time));
    }

    /**
     * DeterministicClock constructor.
     *
     * @param DateTimeInterface $dateTime
     */
    public function __construct(DateTimeInterface $dateTime)
    {
        $this->dateTime = $dateTime;
    }

    /**
     * {@inheritdoc}
     */
    public function now(): int
    {
        return $this->dateTime->getTimestamp();
    }
}
