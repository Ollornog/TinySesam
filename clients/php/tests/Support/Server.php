<?php

declare(strict_types=1);

namespace TinySesam\Gate\Tests\Support;

/**
 * PHP's built-in server with tests/Support/router.php on a free loopback port, in a throwaway directory. Stopped by
 * stop() or when the object goes away.
 */
final class Server
{
    public readonly string $base;
    public readonly string $dir;
    /** @var resource */
    private $process;

    public function __construct(string $jwks = '{"keys":[]}')
    {
        $this->dir = sys_get_temp_dir() . '/tinysesam-gate-test-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0o700);
        $probe = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($probe === false) {
            throw new \RuntimeException("no free port: {$errstr}");
        }
        $name = stream_socket_get_name($probe, false);
        fclose($probe);
        \assert(\is_string($name));
        $this->base = 'http://' . $name;
        $env = getenv();
        $env['TS_HITS'] = $this->dir . '/hits';
        $env['TS_JWKS'] = $jwks;
        $process = proc_open(
            [PHP_BINARY, '-S', $name, __DIR__ . '/router.php'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            $env,
        );
        if ($process === false) {
            throw new \RuntimeException('php -S did not start');
        }
        $this->process = $process;
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            $c = @stream_socket_client('tcp://' . $name, $errno, $errstr, 0.2);
            if ($c !== false) {
                fclose($c);

                return;
            }
            usleep(20_000);
        }
        $this->stop();
        throw new \RuntimeException('php -S did not answer within 10 s');
    }

    /** @return list<string> the paths requested so far */
    public function hits(): array
    {
        $text = @file_get_contents($this->dir . '/hits');

        return $text === false || $text === '' ? [] : explode("\n", rtrim($text, "\n"));
    }

    public function stop(): void
    {
        if (\is_resource($this->process)) {
            proc_terminate($this->process, 9);
            proc_close($this->process);
        }
        $files = glob($this->dir . '/{,.}*', GLOB_BRACE);
        foreach ($files === false ? [] : $files as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
        if (is_dir($this->dir)) {
            rmdir($this->dir);
        }
    }

    public function __destruct()
    {
        $this->stop();
    }

    /**
     * Sends raw request bytes and returns the status code and the body.
     *
     * @return array{0: int, 1: string}
     */
    public function raw(string $request): array
    {
        $c = stream_socket_client('tcp://' . substr($this->base, 7), $errno, $errstr, 5);
        if ($c === false) {
            throw new \RuntimeException("connect: {$errstr}");
        }
        stream_set_timeout($c, 10);
        fwrite($c, $request);
        $response = stream_get_contents($c);
        fclose($c);
        if ($response === false || preg_match('/\AHTTP\/1\.[01] (\d{3})/', $response, $m) !== 1) {
            return [0, ''];
        }
        $split = strpos($response, "\r\n\r\n");

        return [(int) $m[1], $split === false ? '' : substr($response, $split + 4)];
    }
}
