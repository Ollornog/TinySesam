<?php

declare(strict_types=1);

namespace TinySesam\Gate;

/**
 * The `jti` store of spec/approval-token.md section 7: remember() writes the id atomically — one INSERT into a table
 * with a unique key, shared by every PHP worker of the application (not APCu, not process memory) — and answers true
 * only the first time. It may forget the entry after $until (Unix seconds). A thrown exception refuses the
 * confirmation (`internal`).
 *
 * ```php
 * final class PdoJtiStore implements JtiStore
 * {
 *     // CREATE TABLE approval_jti (jti TEXT PRIMARY KEY, until INTEGER NOT NULL)
 *     public function __construct(private \PDO $db) {}
 *     public function remember(string $jti, int $until): bool
 *     {
 *         $insert = $this->db->prepare(
 *             'INSERT INTO approval_jti (jti, until) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING',
 *         );
 *         $insert->execute([$jti, $until]);
 *         return $insert->rowCount() === 1;
 *     }
 * }
 * ```
 */
interface JtiStore
{
    /** Stores $jti until $until; false when it was there already. */
    public function remember(string $jti, int $until): bool;
}
