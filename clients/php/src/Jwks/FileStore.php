<?php

declare(strict_types=1);

namespace TinySesam\Gate\Jwks;

use TinySesam\Gate\ConfigError;

/**
 * The state in a file shared by every PHP process of one host, guarded by flock(2) on a lock file next to it — for
 * PHP-FPM, mod_php and CGI, where nothing survives a request. One process fetches; the others wait for its result at
 * most one deadline, then read it from the file.
 *
 * The file holds only public material (the key set document and three timestamps) but decides which keys the
 * application trusts: give it a directory that only the application's user can write, never a shared temporary one.
 * The timestamps are wall-clock seconds; a timestamp in the future (the clock stepped back, or a copied file) makes the
 * cache fetch again instead of trusting it.
 */
final class FileStore implements Store
{
    /** @var resource|null */
    private $lockHandle;

    /**
     * @param string $path the state file, for example `/var/lib/example/tinysesam-jwks.json`; its directory must exist
     *                     and be writable
     *
     * @throws ConfigError when the directory does not exist or is not writable
     */
    public function __construct(private readonly string $path)
    {
        $dir = \dirname($path);
        if ($path === '' || !is_dir($dir) || !is_writable($dir)) {
            throw new ConfigError('the directory of the key set state file must exist and be writable');
        }
    }

    public function load(): State
    {
        $text = @file_get_contents($this->path);
        if ($text === false || $text === '') {
            return new State();
        }
        $data = json_decode($text, true);
        if (!\is_array($data)) {
            return new State();
        }
        $document = $data['document'] ?? null;
        $freshUntil = $data['fresh_until'] ?? null;
        $lastAttempt = $data['last_attempt'] ?? null;
        if (
            !\is_int($freshUntil) || !(\is_string($document) || $document === null)
            || !(\is_int($lastAttempt) || $lastAttempt === null)
        ) {
            return new State();
        }

        return new State($document, $freshUntil, $lastAttempt);
    }

    public function save(State $state): void
    {
        $json = json_encode(
            [
                'document' => $state->document,
                'fresh_until' => $state->freshUntil,
                'last_attempt' => $state->lastAttempt,
            ],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );
        // Written next to the target and renamed over it, so a reader never sees half a file.
        $tmp = $this->path . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $old = umask(0o077);
        try {
            if (@file_put_contents($tmp, $json) !== \strlen($json) || !@rename($tmp, $this->path)) {
                @unlink($tmp);
            }
        } finally {
            umask($old);
        }
    }

    public function lock(float $timeoutSeconds): bool
    {
        $old = umask(0o077);
        $handle = @fopen($this->path . '.lock', 'c');
        umask($old);
        if ($handle === false) {
            return false;
        }
        $deadline = hrtime(true) + (int) ($timeoutSeconds * 1e9);
        do {
            if (flock($handle, LOCK_EX | LOCK_NB)) {
                $this->lockHandle = $handle;

                return true;
            }
            usleep(10_000);
        } while (hrtime(true) < $deadline);
        fclose($handle);

        return false;
    }

    public function unlock(): void
    {
        if ($this->lockHandle !== null) {
            flock($this->lockHandle, LOCK_UN);
            fclose($this->lockHandle);
            $this->lockHandle = null;
        }
    }

    public function now(): int
    {
        return time();
    }
}
