// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

/**
 * Normalizes a SARIF `artifactLocation.uri` into the absolute path key the inspection
 * looks findings up by.
 *
 * ASH writes paths relative to the directory it scanned, so a finding's raw path is
 * `automated_security_helper/x.py` while the IDE knows the file as
 * `/home/u/proj/automated_security_helper/x.py`. Comparing those two strings directly
 * matches nothing -- and matching nothing is indistinguishable from a clean scan, which
 * is exactly the failure mode this plugin must not have. Kept as a pure function so the
 * mapping is tested directly rather than inferred from annotations appearing.
 *
 * Backslashes are folded to forward slashes on both sides, so a Windows-shaped SARIF
 * path and a Windows IDE path compare equal.
 */
object AshPathResolver {

    /** The key used for both sides of the lookup. */
    fun normalize(path: String): String = path.replace('\\', '/')

    /**
     * @param rawPath a SARIF path, already scheme-stripped by [AshSarifParser].
     * @param projectBasePath the project root, or null when the project has none.
     * @param exists how existence is decided. Injected so the resolution rules can be tested
     *   without creating files, and so a test can describe a checkout that does not exist on the
     *   machine running it.
     */
    fun toAbsoluteKey(
        rawPath: String,
        projectBasePath: String?,
        exists: (String) -> Boolean = { java.io.File(it).exists() },
    ): String {
        val path = normalize(rawPath).trim()
        val base = projectBasePath
            ?.let { normalize(it).trimEnd('/') }
            ?.takeIf { it.isNotEmpty() }

        // A LEADING SLASH DOES NOT MEAN FILESYSTEM-ABSOLUTE. grype reports paths relative to the
        // scan root WITH a leading slash -- `/poetry.lock`, `/.venv/lib/.../yarn.lock` -- and 14
        // of the 126 results in the real report are exactly that shape, all of them grype, none
        // of which exist at that absolute location.
        //
        // Returning such a path unjoined does not misplace the finding, it ERASES it:
        // AshScanService keys findings by this string and looks them up by the open file's real
        // path, so `/poetry.lock` can never match `/home/u/proj/poetry.lock`. No error, no log
        // line, and a Problems view that looks right because it is merely short.
        //
        // The resolution order below is MONOTONE, which is the property that makes it safe: each
        // step only returns a path that exists, so a finding can move from a path that does not
        // exist to one that does and never the other way. A currently-correct resolution cannot
        // break.
        if (isAbsolute(path)) {
            val asAbsolute = collapse(path)
            // 1. It exists as written, so it really was absolute -- ASH pointed at a directory
            //    outside the project, which is legitimate.
            if (exists(asAbsolute)) return asAbsolute
            // 2. It does not, so try it as scan-root-relative. JOINED, never resolved: a resolve()
            //    discards the base when the second argument is absolute, which is this same bug in
            //    a different costume.
            if (base != null) {
                val joined = collapse("$base/${path.removePrefix("/")}")
                if (exists(joined)) return joined
            }
            // 3. Neither exists. Unchanged from before the fix, so nothing that used to work
            //    changes; a key that matches nothing is at least not a key that matches the wrong
            //    file.
            return asAbsolute
        }

        if (base == null) return collapse(path)
        return collapse("$base/${path.removePrefix("./")}")
    }

    /**
     * Treats a Windows drive path as absolute as well as a POSIX one. Without the
     * drive-letter arm, `C:/x/y.tf` would be treated as relative and joined onto the
     * project root, producing a path no file has.
     */
    private fun isAbsolute(path: String): Boolean =
        path.startsWith("/") || (path.length >= 3 && path[1] == ':' && path[2] == '/')

    /**
     * Removes `.` segments and resolves `..` against the preceding segment.
     *
     * Done textually rather than with `File.getCanonicalPath` on purpose: canonicalizing
     * touches the filesystem and resolves symlinks, so the key it produces for a file
     * inside a symlinked project root would not match the key derived from the path the
     * IDE reports. A textual collapse is the same on both sides.
     */
    private fun collapse(path: String): String {
        val absolute = path.startsWith("/")
        val out = ArrayDeque<String>()
        for (segment in path.split('/')) {
            when {
                segment.isEmpty() || segment == "." -> Unit
                segment == ".." -> if (out.isNotEmpty() && out.last() != "..") out.removeLast() else out.addLast(segment)
                else -> out.addLast(segment)
            }
        }
        val joined = out.joinToString("/")
        return if (absolute) "/$joined" else joined
    }
}
