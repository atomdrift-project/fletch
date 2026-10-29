//! Modules a language runtime provides, which an import never fetches from a
//! registry. Each table is sorted, so a lookup is a binary search.

/// Modules a host runtime injects into the code it loads, never installed from
/// npm. `vscode` is the VS Code extension-host API, which the editor provides
/// to every extension; the npm package of that name is an unrelated, long
/// deprecated test harness. List only modules a host genuinely injects.
const HOST_PROVIDED_MODULES: &[&str] = &["vscode"];

/// Node.js builtin modules: a dynamic `import("fs")` loads the runtime, not an
/// external dependency.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// Python's standard-library top-level modules: `sys.stdlib_module_names` as of
/// 3.14, plus the modules 3.12 and 3.13 removed, which code written for older
/// interpreters still imports. A dynamic `import_module("csv")` is the runtime,
/// not an external dependency; a PyPI project of the same name is a backport
/// or a squat, and neither is what the code loads.
#[rustfmt::skip]
const PY_STDLIB: &[&str] = &[
    "__future__", "__main__", "_abc", "_aix_support", "_android_support", "_apple_support", "_ast",
    "_ast_unparse", "_asyncio", "_bisect", "_blake2", "_bz2", "_codecs", "_codecs_cn",
    "_codecs_hk", "_codecs_iso2022", "_codecs_jp", "_codecs_kr", "_codecs_tw", "_collections",
    "_collections_abc", "_colorize", "_compat_pickle", "_contextvars", "_csv", "_ctypes",
    "_curses", "_curses_panel", "_datetime", "_dbm", "_decimal", "_elementtree",
    "_frozen_importlib", "_frozen_importlib_external", "_functools", "_gdbm", "_hashlib", "_heapq",
    "_hmac", "_imp", "_interpchannels", "_interpqueues", "_interpreters", "_io", "_ios_support",
    "_json", "_locale", "_lsprof", "_lzma", "_markupbase", "_md5", "_multibytecodec",
    "_multiprocessing", "_opcode", "_opcode_metadata", "_operator", "_osx_support", "_overlapped",
    "_pickle", "_posixshmem", "_posixsubprocess", "_py_abc", "_py_warnings", "_pydatetime",
    "_pydecimal", "_pyio", "_pylong", "_pyrepl", "_queue", "_random", "_remote_debugging",
    "_scproxy", "_sha1", "_sha2", "_sha3", "_signal", "_sitebuiltins", "_socket", "_sqlite3",
    "_sre", "_ssl", "_stat", "_statistics", "_string", "_strptime", "_struct", "_suggestions",
    "_symtable", "_sysconfig", "_thread", "_threading_local", "_tkinter", "_tokenize",
    "_tracemalloc", "_types", "_typing", "_uuid", "_warnings", "_weakref", "_weakrefset",
    "_winapi", "_wmi", "_zoneinfo", "_zstd", "abc", "aifc", "annotationlib", "antigravity",
    "argparse", "array", "ast", "asynchat", "asyncio", "asyncore", "atexit", "audioop", "base64",
    "bdb", "binascii", "bisect", "builtins", "bz2", "cProfile", "calendar", "cgi", "cgitb",
    "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections", "colorsys", "compileall",
    "compression", "concurrent", "configparser", "contextlib", "contextvars", "copy", "copyreg",
    "crypt", "csv", "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal", "difflib",
    "dis", "distutils", "doctest", "email", "encodings", "ensurepip", "enum", "errno",
    "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "fractions", "ftplib", "functools",
    "gc", "genericpath", "getopt", "getpass", "gettext", "glob", "graphlib", "grp", "gzip",
    "hashlib", "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr", "imp", "importlib",
    "inspect", "io", "ipaddress", "itertools", "json", "keyword", "lib2to3", "linecache", "locale",
    "logging", "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
    "modulefinder", "msilib", "msvcrt", "multiprocessing", "netrc", "nis", "nntplib", "nt",
    "ntpath", "nturl2path", "numbers", "opcode", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform", "plistlib",
    "poplib", "posix", "posixpath", "pprint", "profile", "pstats", "pty", "pwd", "py_compile",
    "pyclbr", "pydoc", "pydoc_data", "pyexpat", "queue", "quopri", "random", "re", "readline",
    "reprlib", "resource", "rlcompleter", "runpy", "sched", "secrets", "select", "selectors",
    "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr", "socket",
    "socketserver", "spwd", "sqlite3", "sre_compile", "sre_constants", "sre_parse", "ssl", "stat",
    "statistics", "string", "stringprep", "struct", "subprocess", "sunau", "symtable", "sys",
    "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "textwrap",
    "this", "threading", "time", "timeit", "tkinter", "token", "tokenize", "tomllib", "trace",
    "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing", "unicodedata",
    "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
    "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport",
    "zlib", "zoneinfo",
];

/// Whether `module` is a Node.js builtin.
pub(super) fn is_node_builtin(module: &str) -> bool {
    NODE_BUILTINS.binary_search(&module).is_ok()
}

/// Whether a host runtime injects `module`.
pub(super) fn is_host_provided(module: &str) -> bool {
    HOST_PROVIDED_MODULES.binary_search(&module).is_ok()
}

/// Whether `module` is a top-level Python standard-library module.
pub(super) fn is_python_stdlib(module: &str) -> bool {
    PY_STDLIB.binary_search(&module).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted_and_distinct_for_binary_search() {
        for table in [HOST_PROVIDED_MODULES, NODE_BUILTINS, PY_STDLIB] {
            assert!(table.windows(2).all(|w| w[0] < w[1]), "{table:?}");
        }
    }

    #[test]
    fn lookups_find_members_only() {
        assert!(is_node_builtin("fs") && is_node_builtin("zlib") && !is_node_builtin("lodash"));
        assert!(is_host_provided("vscode") && !is_host_provided("vscode-test"));
        assert!(is_python_stdlib("__future__") && is_python_stdlib("cProfile"));
        assert!(is_python_stdlib("zoneinfo") && !is_python_stdlib("requests"));
    }
}
