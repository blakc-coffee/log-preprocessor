# Fan-out

Fan-out gives each target an independent bounded queue and worker. Writes
back-pressure when a queue is full; failed batches retry, then enter the
target's durable spool. `Metrics` exposes lag, errors, spool bytes, batch count,
write duration, and health without coupling the package to a metrics library.

