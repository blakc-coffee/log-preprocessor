# CEF syslog

The exporter emits CEF 0 inside RFC 5424 headers over UDP or TCP. TCP supports
LF and octet-counted framing. Header and extension escaping are tested for
pipes, equals signs, backslashes, newlines, and UTF-8 text.

