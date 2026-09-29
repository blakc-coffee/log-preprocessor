# Disk spool

Each batch is an immutable, ordered segment containing a magic header, bounded
length, JSON payload, and CRC32. Publication uses write, fsync, rename, and
directory fsync on Unix. Restart removes incomplete `.tmp` files and replays
complete segments in lexical sequence order.

