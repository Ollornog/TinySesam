<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/** Whether a request came from a browser session or from a token (OAuth, API key, app password). */
enum Kind: string
{
    case Session = 'session';
    case Token = 'token';
}
