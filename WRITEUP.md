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

## Section 6: Unsafe Code Removal (A Grade)

### Unsafe Block Statistics
- **Total unsafe occurrences**: 10
- **Unsafe functions**: 9
- **Unsafe blocks in main**: 1
- **Percentage of code that is unsafe**: ~95% (almost all functions)

### Analysis of Unsafe Code

The C2Rust tool generates code that is heavily reliant on `unsafe` because it directly translates C idioms:
- All FFI calls to C libraries (libc, libsodium)
- Raw pointer manipulations
- Mutable static variables
- Manual memory management (malloc/free patterns)

---

### Unsafe Block #1: FFI Calls to libc (File I/O)

**Location**: Throughout `ensure_db_initialized()` (lines 225-281)

**Original Unsafe Code**:
```rust
unsafe extern "C" fn ensure_db_initialized(
    mut out_fp: *mut *mut FILE,
) -> core::ffi::c_int {
    let mut fp: *mut FILE = fopen(
        DB_FILE,
        b"r+b\0" as *const u8 as *const core::ffi::c_char,
    );
    if fp.is_null() { /* ... */ }
    fread(magic.as_mut_ptr() as *mut core::ffi::c_void, 1, 8, fp);
    *out_fp = fp;  // Raw pointer dereference
}
```

**Why Rust marks this as unsafe**:
1. **FFI Boundary**: Calls to C functions (`fopen`, `fread`, `fwrite`, `fclose`) bypass Rust's safety checks
2. **Null pointer risks**: `fp` can be null, leading to null pointer dereference
3. **Resource leaks**: If panic occurs, file descriptor will leak (no RAII)
4. **Buffer overflows**: `fread` doesn't check buffer bounds
5. **Double-free**: Manual close can lead to use-after-free if called twice
6. **Raw pointer dereference**: `*out_fp = fp` can write to invalid memory

**Safe Rust Alternative**:
```rust
fn ensure_db_initialized() -> Result<File, StorError> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open(DB_FILE)
    {
        Ok(mut file) => {
            let mut magic = [0u8; 8];
            file.read_exact(&mut magic)?;
            if &magic != DB_MAGIC {
                return Err(StorError::InvalidFormat);
            }
            file.seek(SeekFrom::End(0))?;
            Ok(file)
        }
        Err(_) => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(DB_FILE)?;
            file.write_all(DB_MAGIC)?;
            file.flush()?;
            Ok(file)
        }
    }
}
```

**Why this is better**:
- **Automatic resource management**: `File` implements `Drop`, guaranteeing cleanup even on panic
- **No null pointers**: Rust's `Option<File>` and `Result` make error states explicit
- **Bounds checking**: `read_exact()` validates buffer size at runtime
- **Type safety**: Can't pass wrong type to file operations
- **Prevents vulnerabilities**:
  - **CWE-401** (Memory Leak): Drop trait ensures file descriptor is closed
  - **CWE-476** (NULL Pointer Dereference): Type system prevents null
  - **CWE-119** (Buffer Overflow): Bounds checking in read operations
  - **CWE-415** (Double Free): Ownership system prevents multiple closes
  - **CWE-416** (Use After Free): Borrow checker ensures no access after close

---

### Unsafe Block #2: Mutable Static Variables

**Location**: Lines 206-221

**Original Unsafe Code**:
```rust
static mut DB_FILE: *const core::ffi::c_char = b"enc.db\0" as *const u8;
static mut DB_MAGIC: [uint8_t; 8] = [/* ... */];
static mut g_suppress_write_message: core::ffi::c_int = 0;

// Usage (creates shared reference to mutable static):
DB_MAGIC.as_ptr()  // Warning: creating shared reference to mutable static
```

**Why Rust marks this as unsafe**:
1. **Data races**: Multiple threads can access mutable static simultaneously
2. **Undefined behavior**: Creating shared reference to mutable static is UB if mutated
3. **No synchronization**: No mutex or atomic protection
4. **Aliasing violations**: Can have both mutable and immutable references

**Safe Rust Alternative**:
```rust
// Option 1: Use const (immutable)
const DB_FILE: &str = "enc.db";
const DB_MAGIC: &[u8; 8] = b"STORDB1\n";

// Option 2: Use thread-safe wrapper for mutable state
use std::sync::atomic::{AtomicBool, Ordering};
static SUPPRESS_WRITE: AtomicBool = AtomicBool::new(false);
```

**Why this is better**:
- **No data races**: `const` is immutable and safe to share across threads
- **Compiler optimizations**: Compiler can inline constants
- **Atomics for mutable state**: `AtomicBool` provides safe concurrent access
- **Prevents vulnerabilities**:
  - **CWE-362** (Concurrent Execution using Shared Resource): Atomics prevent race conditions
  - **CWE-667** (Improper Locking): Atomic operations are lock-free but safe

---

### Unsafe Block #3: Raw Pointer Manipulation and Memory Allocation

**Location**: `scan_for_user_auth()` lines 350-370 (example)

**Original Unsafe Code**:
```rust
let mut uname: *mut core::ffi::c_char = malloc((ulen + 1) as size_t) as *mut core::ffi::c_char;
if uname.is_null() { /* error */ }
fread(uname as *mut core::ffi::c_void, 1, ulen, fp);
*uname.offset(ulen as isize) = 0;  // null terminator
// ... use uname ...
free(uname as *mut core::ffi::c_void);
```

**Why Rust marks this as unsafe**:
1. **Manual memory management**: Programmer must remember to free
2. **Null check burden**: Forgot null check = crash
3. **Pointer arithmetic**: `.offset()` can go out of bounds
4. **Double free**: If `free()` called twice, corruption
5. **Memory leak**: If forget to free or early return
6. **Use after free**: Access after `free()` is undefined behavior

**Safe Rust Alternative**:
```rust
// Option 1: Use String for text
let uname = String::from_utf8(buffer)
    .map_err(|_| StorError::InvalidUtf8)?;

// Option 2: Use Vec for binary data
let mut buffer = vec![0u8; ulen];
file.read_exact(&mut buffer)?;

// Option 3: Safe C string handling
use std::ffi::CString;
let c_string = CString::new(data)
    .map_err(|_| StorError::NullByte)?;
```

**Why this is better**:
- **Automatic deallocation**: `String`/`Vec` automatically free memory when dropped
- **No null checks needed**: Type system prevents null
- **Bounds checking**: Vec access is checked or uses safe slicing
- **UTF-8 validation**: String guarantees valid UTF-8
- **Prevents vulnerabilities**:
  - **CWE-401** (Memory Leak): RAII guarantees cleanup
  - **CWE-415** (Double Free): Ownership prevents multiple frees
  - **CWE-416** (Use After Free): Borrow checker prevents access after free
  - **CWE-125** (Out-of-bounds Read): Bounds checking catches overruns
  - **CWE-787** (Out-of-bounds Write): Vec::push checks capacity

---

### Unsafe Block #4: Cryptographic Operations (FFI to libsodium)

**Location**: `derive_user_key()` lines 283-302, `cmd_write()` encryption sections

**Original Unsafe Code**:
```rust
unsafe extern "C" fn derive_user_key(
    mut token: *const core::ffi::c_char,
    mut salt: *const uint8_t,
    mut key: *mut uint8_t,
) -> core::ffi::c_int {
    crypto_pwhash(
        key as *mut core::ffi::c_uchar,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        token,
        strlen(token),
        salt,
        KDF_OPSLIMIT, KDF_MEMLIMIT,
        crypto_pwhash_ALG_DEFAULT
    );
    // Key stays in memory, might not be zeroed on panic
}
```

**Why Rust marks this as unsafe**:
1. **FFI to C library**: No Rust safety guarantees
2. **Raw pointers for sensitive data**: Key could leak via debugger/core dump
3. **Manual zeroization**: Programmer must remember `sodium_memzero()`
4. **Panic safety**: If panic before zeroization, key leaks
5. **Type confusion**: Easy to pass wrong buffer size

**Safe Rust Alternative**:
```rust
use sodiumoxide::crypto::pwhash;
use secrecy::{Secret, ExposeSecret, Zeroize};

fn derive_user_key(password: &str, salt: &[u8; 16]) -> Result<Secret<Key>, CryptoError> {
    // sodiumoxide provides safe Rust bindings
    let key = pwhash::derive_key(
        password.as_bytes(),
        &Salt::from_slice(salt).ok_or(CryptoError::InvalidSalt)?,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    ).map_err(|_| CryptoError::DeriveKeyFailed)?;
    
    // Wrap in Secret for automatic zeroization
    Ok(Secret::new(key))
}

// Secret<T> implements Drop with zeroization
impl Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();  // Always called, even on panic
    }
}
```

**Why this is better**:
- **Type-safe crypto**: `sodiumoxide` wraps libsodium with Rust types (Key, Nonce, Salt)
- **Automatic zeroization**: `Secret<T>` zeros memory in Drop, even on panic
- **Compile-time size checking**: Types encode key/nonce sizes
- **No accidental leaks**: Can't accidentally print/debug Secret values
- **Prevents vulnerabilities**:
  - **CWE-316** (Cleartext Storage in Memory): Automatic zeroization
  - **CWE-200** (Information Exposure): Secret type prevents accidental logging
  - **CWE-327** (Use of Broken Crypto): sodiumoxide uses modern, audited primitives
  - **CWE-330** (Insufficient Randomness): Uses OS-provided secure random

---

### Unsafe Block #5: C String Handling

**Location**: Throughout (strlen, strcmp calls)

**Original Unsafe Code**:
```rust
strlen(token);  // No null terminator = buffer overrun
strcmp(uname, username);  // Undefined if not null-terminated
```

**Why Rust marks this as unsafe**:
1. **Assumption of null termination**: C strings must end with \0
2. **Buffer overruns**: If no null terminator, reads past end
3. **Encoding issues**: C strings are just bytes, not validated UTF-8

**Safe Rust Alternative**:
```rust
use std::ffi::CStr;

fn c_str_to_string(ptr: *const i8) -> Result<String, StorError> {
    if ptr.is_null() {
        return Err(StorError::NullPointer);
    }
    unsafe {
        CStr::from_ptr(ptr)
            .to_str()  // Validates UTF-8
            .map(|s| s.to_string())
            .map_err(|_| StorError::InvalidUtf8)
    }
}

// Then use normal Rust string operations
if username1 == username2 {  // Safe comparison
    // ...
}
```

**Why this is better**:
- **Validates null termination**: `CStr::from_ptr` finds null terminator safely (still unsafe but isolated)
- **UTF-8 validation**: `to_str()` ensures valid encoding
- **Error handling**: Returns `Result` instead of UB
- **Prevents vulnerabilities**:
  - **CWE-120** (Buffer Overflow): Validation prevents overrun
  - **CWE-134** (Format String Vulnerability): Rust doesn't use format strings
  - **CWE-170** (Improper Null Termination): CStr validates termination

---

### Unsafe Block #6: Function Pointers and extern "C"

**Location**: All function signatures

**Original Unsafe Code**:
```rust
pub unsafe extern "C" fn win() { /* ... */ }
unsafe extern "C" fn cmd_register(/* ... */) { /* ... */ }
```

**Why marked as unsafe**:
1. **C calling convention**: Must match C expectations exactly
2. **No panic unwinding**: Panics across FFI boundary are undefined behavior
3. **No type checking across boundary**: C can call with wrong types

**Safe Rust Alternative**:
```rust
// Internal safe functions
pub fn win() {
    println!("Arbitrary access achieved!");
}

// Thin FFI wrapper (only this is unsafe)
#[no_mangle]
pub extern "C" fn stor_win() {
    std::panic::catch_unwind(|| {
        win();
    }).ok();  // Don't panic across FFI
}
```

**Why this is better**:
- **Panic safety**: `catch_unwind` prevents UB from panic across FFI
- **Clear boundary**: Only wrapper is unsafe, logic is safe
- **Testable**: Can unit test safe `win()` without FFI concerns
- **Prevents vulnerabilities**:
  - **CWE-248** (Uncaught Exception): catch_unwind handles panics
  - **Undefined Behavior**: Panic across FFI causes stack corruption

---

### Summary of Improvements

| Unsafe Pattern | Safe Alternative | Vulnerabilities Prevented |
|----------------|------------------|---------------------------|
| fopen/fclose | std::fs::File | CWE-401 (leak), CWE-415 (double-free) |
| malloc/free | Vec/Box | CWE-401, CWE-416 (use-after-free) |
| Raw pointers | References/Box | CWE-476 (null deref), CWE-416 |
| mutable static | const/Atomic | CWE-362 (race condition) |
| strlen/strcmp | String/CStr | CWE-120 (overflow), CWE-170 |
| libsodium FFI | sodiumoxide | CWE-316 (cleartext in memory) |
| Manual zeroing | Secret<T> with Drop | CWE-316 (key leakage) |
| Bounds-unchecked access | Checked indexing | CWE-125/787 (buffer overrun) |

### Implementation Status

✅ **Created `src/safe_stor.rs`** with safe implementations of:
- Database initialization (File instead of FILE*)
- Constant definitions (const instead of static mut)
- Error handling (Result<T, E> instead of return codes)
- Safe string conversion helpers

🔄 **Remaining work** (would require full rewrite):
- Complete safe versions of all commands (register, read, write, create)
- Integrate sodiumoxide for cryptography
- Replace all C FFI calls
- Add comprehensive error handling
- Write unit tests for safe code

### Key Learnings

1. **C2Rust is a starting point, not a solution**: Generated code is unsafe by design
2. **Rust's safety comes from idioms, not just syntax**: Must rewrite in Rust style
3. **Type system prevents entire vulnerability classes**: Memory safety bugs become compile errors
4. **Error handling is enforced**: Can't ignore errors like in C
5. **Trade-off**: Safety requires more upfront design but eliminates runtime bugs

