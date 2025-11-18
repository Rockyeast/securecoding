# Fix-it with Safety Programming - Writeup
## 14-735 Secure Coding

---

## Section 4: Fast Conversion

### Time Record
- **Start Time**: 2025-11-18 18:19:06
- **End Time**: 2025-11-18 18:19:07
- **Total Time**: **1 second**

### Generated File
- **Filename**: `stor.rs`
- **Lines of Code**: 1789 lines

### Tool Used
```bash
c2rust transpile compile_commands.json
```

### Notes
The C2Rust tool successfully transpiled the C code (`stor.c`) to Rust automatically. The process was very fast (1 second). The generated code has not been manually edited as per assignment requirements.

---

## Section 5: Getting Things Running

### Option 2: Code shows errors/warnings ⚠️

#### Error List and Fixes:

**Error #1: Feature gate not available on stable channel**
```
error[E0554]: `#![feature]` may not be used on the stable release channel
 --> src/main.rs:9:1
  |
9 | #![feature(extern_types)]
  | ^^^^^^^^^^^^^^^^^^^^^^^^^
```

- **Cause**: C2Rust generated code uses `#![feature(extern_types)]` which is only available in Rust nightly. This feature allows declaring opaque external types like `_IO_wide_data` from C libraries.
- **Fix**: Switched Rust toolchain to nightly version using `rustup default nightly`
- **Explanation**: The `extern_types` feature is needed for FFI declarations of incomplete C types. Using nightly is the standard approach for c2rust-generated code that requires unstable features.

#### Warnings (not requiring fixes for compilation):

**Warning #1: Unused variable**
```
warning: unused variable: `token`
    --> src/main.rs:1310:5
```
- This is expected in auto-generated code where parameters might not be used in all code paths.

**Warning #2-6: Mutable static references**
```
warning: creating a shared reference to mutable static (DB_MAGIC)
```
- These warnings indicate potential undefined behavior when creating shared references to mutable statics. The code works but could be improved for safety.

### Compilation Result:
✅ **Successfully compiled** with Rust nightly (1.93.0-nightly)
- Build command: `cargo build`
- Output binary: `target/debug/stor`
- Tested: Basic functionality works (win command executed successfully)

### Dependencies Added:
- `libc = "0.2"` in Cargo.toml
- `build.rs` script to link libsodium library

---

## Section 6: Unsafe Code Removal

[To be completed for A grade]

