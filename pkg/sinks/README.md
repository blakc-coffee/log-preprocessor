# Export sinks

All sinks implement the frozen `types.Sink` contract. Fan-out provides bounded
per-target queues, retry, and durable spool fallback. Raw vault bytes are not
available to exporters unless an operator explicitly configures a raw provider.

