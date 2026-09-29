# Splunk HEC

Tokens are read only from a file. TLS verification is always enabled and may
use an additional CA bundle. Network errors, 429, and 5xx are retryable;
non-429 4xx responses are classified as permanent and can be written to a
dead-letter spool.

