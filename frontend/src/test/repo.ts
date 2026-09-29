// Test-only access to files owned by other workstreams, read in place (never
// copied): the contract's goldens and Ingestion's Merkle vectors.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(__dirname, '../../..');

export function golden<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(root, 'contracts/golden', `${name}.json`), 'utf8')) as T;
}

export function merkleVectors<T>(): T {
  return JSON.parse(readFileSync(resolve(root, 'testdata/merkle_vectors.json'), 'utf8')) as T;
}
