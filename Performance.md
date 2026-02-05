# Tokenization Performance Results

Dataset: `words_alpha.txt` (370,104 lines, 3.33 MB)
Policy: `policy_simple.json` (DataToken, no filter, no offset)
Platform: macOS Darwin 24.6.0, Apple Silicon (ARM64)

## Cross-Project Chain Tests

All 5 projects produce byte-identical tokenized output (verified with `xxd`).
Chain tests confirm full cross-project interoperability.

### Forward Chain: Java -> Zig -> Odin -> JNI

| Step | Project | Operation  | Time (sec) | Speed (lines/sec) |
|------|---------|------------|------------|-------------------|
| 1    | Java    | TOKENIZE   | 19.427     | 19,051            |
| 2    | Zig     | DETOKENIZE | 17.529     | 21,114            |
| 3    | Odin    | TOKENIZE   | 17.094     | 21,651            |
| 4    | JNI     | DETOKENIZE | 8.744      | 42,325            |
| **Total** |    |            | **62.794** |                   |

Result: **PASS** (diff with original = empty)

### Reverse Chain: JNI -> Odin -> Zig -> Java

| Step | Project | Operation  | Time (sec) | Speed (lines/sec) |
|------|---------|------------|------------|-------------------|
| 1    | JNI     | TOKENIZE   | 8.928      | 41,452            |
| 2    | Odin    | DETOKENIZE | 17.029     | 21,734            |
| 3    | Zig     | TOKENIZE   | 18.576     | 19,923            |
| 4    | Java    | DETOKENIZE | 19.267     | 19,209            |
| **Total** |    |            | **63.800** |                   |

Result: **PASS** (diff with original = empty)

## Per-Project Round-Trip Benchmarks

Single-project ROUNDTRIP (tokenize + detokenize every line, verify match):

| Rank | Project | Language | Time (sec) | Speed (lines/sec) | Speed (MB/sec) |
|------|---------|----------|------------|-------------------|----------------|
| 1    | C       | C        | 17.345     | 21,338            | 0.19           |
| 2    | JNI     | Java/C   | 19.086     | 19,391            | 0.17           |
| 3    | Zig     | Zig      | 31.778     | 11,647            | 0.10           |
| 4    | Odin    | Odin     | 33.143     | 11,167            | 0.10           |
| 5    | Java    | Java     | 38.368     | 9,646             | 0.09           |

All projects: **0 errors** on 370,104 lines.

## Notes

- All projects use single-byte (Latin-1) encoding for the tokenization alphabet
- Non-ASCII characters (0x80-0xFF) are stored and transmitted as single bytes
- Zig built with `-Doptimize=ReleaseFast` (Debug mode was 6.7x slower)
- Odin built with `-o:speed`
- C built with `-O3`
- JNI combines Java convenience with native C performance via JNI bridge
- C is fastest due to zero overhead (direct byte-level Feistel cipher with OpenSSL)
