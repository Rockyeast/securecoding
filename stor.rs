#![allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> core::ffi::c_int;
    fn fflush(__stream: *mut FILE) -> core::ffi::c_int;
    fn fopen(
        __filename: *const core::ffi::c_char,
        __modes: *const core::ffi::c_char,
    ) -> *mut FILE;
    fn fprintf(
        __stream: *mut FILE,
        __format: *const core::ffi::c_char,
        ...
    ) -> core::ffi::c_int;
    fn printf(__format: *const core::ffi::c_char, ...) -> core::ffi::c_int;
    fn fread(
        __ptr: *mut core::ffi::c_void,
        __size: size_t,
        __n: size_t,
        __stream: *mut FILE,
    ) -> core::ffi::c_ulong;
    fn fwrite(
        __ptr: *const core::ffi::c_void,
        __size: size_t,
        __n: size_t,
        __s: *mut FILE,
    ) -> core::ffi::c_ulong;
    fn fseek(
        __stream: *mut FILE,
        __off: core::ffi::c_long,
        __whence: core::ffi::c_int,
    ) -> core::ffi::c_int;
    fn ftell(__stream: *mut FILE) -> core::ffi::c_long;
    fn fileno(__stream: *mut FILE) -> core::ffi::c_int;
    fn malloc(__size: size_t) -> *mut core::ffi::c_void;
    fn realloc(__ptr: *mut core::ffi::c_void, __size: size_t) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn memcpy(
        __dest: *mut core::ffi::c_void,
        __src: *const core::ffi::c_void,
        __n: size_t,
    ) -> *mut core::ffi::c_void;
    fn memcmp(
        __s1: *const core::ffi::c_void,
        __s2: *const core::ffi::c_void,
        __n: size_t,
    ) -> core::ffi::c_int;
    fn strcmp(
        __s1: *const core::ffi::c_char,
        __s2: *const core::ffi::c_char,
    ) -> core::ffi::c_int;
    fn strlen(__s: *const core::ffi::c_char) -> size_t;
    fn fsync(__fd: core::ffi::c_int) -> core::ffi::c_int;
    static mut optarg: *mut core::ffi::c_char;
    static mut optind: core::ffi::c_int;
    fn getopt(
        ___argc: core::ffi::c_int,
        ___argv: *const *mut core::ffi::c_char,
        __shortopts: *const core::ffi::c_char,
    ) -> core::ffi::c_int;
    fn sodium_init() -> core::ffi::c_int;
    fn crypto_aead_xchacha20poly1305_ietf_encrypt(
        c: *mut core::ffi::c_uchar,
        clen_p: *mut core::ffi::c_ulonglong,
        m: *const core::ffi::c_uchar,
        mlen: core::ffi::c_ulonglong,
        ad: *const core::ffi::c_uchar,
        adlen: core::ffi::c_ulonglong,
        nsec: *const core::ffi::c_uchar,
        npub: *const core::ffi::c_uchar,
        k: *const core::ffi::c_uchar,
    ) -> core::ffi::c_int;
    fn crypto_aead_xchacha20poly1305_ietf_decrypt(
        m: *mut core::ffi::c_uchar,
        mlen_p: *mut core::ffi::c_ulonglong,
        nsec: *mut core::ffi::c_uchar,
        c: *const core::ffi::c_uchar,
        clen: core::ffi::c_ulonglong,
        ad: *const core::ffi::c_uchar,
        adlen: core::ffi::c_ulonglong,
        npub: *const core::ffi::c_uchar,
        k: *const core::ffi::c_uchar,
    ) -> core::ffi::c_int;
    fn crypto_generichash(
        out: *mut core::ffi::c_uchar,
        outlen: size_t,
        in_0: *const core::ffi::c_uchar,
        inlen: core::ffi::c_ulonglong,
        key: *const core::ffi::c_uchar,
        keylen: size_t,
    ) -> core::ffi::c_int;
    fn crypto_pwhash(
        out: *mut core::ffi::c_uchar,
        outlen: core::ffi::c_ulonglong,
        passwd: *const core::ffi::c_char,
        passwdlen: core::ffi::c_ulonglong,
        salt: *const core::ffi::c_uchar,
        opslimit: core::ffi::c_ulonglong,
        memlimit: size_t,
        alg: core::ffi::c_int,
    ) -> core::ffi::c_int;
    fn randombytes_buf(buf: *mut core::ffi::c_void, size: size_t);
    fn sodium_memzero(pnt: *mut core::ffi::c_void, len: size_t);
    fn sodium_memcmp(
        b1_: *const core::ffi::c_void,
        b2_: *const core::ffi::c_void,
        len: size_t,
    ) -> core::ffi::c_int;
}
pub type size_t = usize;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __off_t = core::ffi::c_long;
pub type __off64_t = core::ffi::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: core::ffi::c_int,
    pub _IO_read_ptr: *mut core::ffi::c_char,
    pub _IO_read_end: *mut core::ffi::c_char,
    pub _IO_read_base: *mut core::ffi::c_char,
    pub _IO_write_base: *mut core::ffi::c_char,
    pub _IO_write_ptr: *mut core::ffi::c_char,
    pub _IO_write_end: *mut core::ffi::c_char,
    pub _IO_buf_base: *mut core::ffi::c_char,
    pub _IO_buf_end: *mut core::ffi::c_char,
    pub _IO_save_base: *mut core::ffi::c_char,
    pub _IO_backup_base: *mut core::ffi::c_char,
    pub _IO_save_end: *mut core::ffi::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: core::ffi::c_int,
    pub _flags2: core::ffi::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: core::ffi::c_ushort,
    pub _vtable_offset: core::ffi::c_schar,
    pub _shortbuf: [core::ffi::c_char; 1],
    pub _lock: *mut core::ffi::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut core::ffi::c_void,
    pub __pad5: size_t,
    pub _mode: core::ffi::c_int,
    pub _unused2: [core::ffi::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type record_type = core::ffi::c_uint;
pub const REC_CREATE: record_type = 4;
pub const REC_DELETE: record_type = 3;
pub const REC_WRITE: record_type = 2;
pub const REC_REGISTER: record_type = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct seg_t {
    pub pos: core::ffi::c_long,
    pub clen: uint32_t,
    pub nonce: [uint8_t; 24],
}
pub const NULL: *mut core::ffi::c_void = 0 as *mut core::ffi::c_void;
pub const SEEK_SET: core::ffi::c_int = 0 as core::ffi::c_int;
pub const SEEK_CUR: core::ffi::c_int = 1 as core::ffi::c_int;
pub const SEEK_END: core::ffi::c_int = 2 as core::ffi::c_int;
pub const crypto_aead_xchacha20poly1305_ietf_KEYBYTES: core::ffi::c_uint = 32
    as core::ffi::c_uint;
pub const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: core::ffi::c_uint = 24
    as core::ffi::c_uint;
pub const crypto_aead_xchacha20poly1305_ietf_ABYTES: core::ffi::c_uint = 16
    as core::ffi::c_uint;
pub const crypto_generichash_blake2b_BYTES: core::ffi::c_uint = 32 as core::ffi::c_uint;
pub const crypto_generichash_BYTES: core::ffi::c_uint = crypto_generichash_blake2b_BYTES;
pub const crypto_pwhash_argon2id_ALG_ARGON2ID13: core::ffi::c_int = 2
    as core::ffi::c_int;
pub const crypto_pwhash_argon2id_SALTBYTES: core::ffi::c_uint = 16 as core::ffi::c_uint;
pub const crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE: core::ffi::c_uint = 2
    as core::ffi::c_uint;
pub const crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE: core::ffi::c_uint = 67108864
    as core::ffi::c_uint;
pub const crypto_pwhash_ALG_ARGON2ID13: core::ffi::c_int = crypto_pwhash_argon2id_ALG_ARGON2ID13;
pub const crypto_pwhash_ALG_DEFAULT: core::ffi::c_int = crypto_pwhash_ALG_ARGON2ID13;
pub const crypto_pwhash_SALTBYTES: core::ffi::c_uint = crypto_pwhash_argon2id_SALTBYTES;
pub const crypto_pwhash_OPSLIMIT_INTERACTIVE: core::ffi::c_uint = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;
pub const crypto_pwhash_MEMLIMIT_INTERACTIVE: core::ffi::c_uint = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE;
#[no_mangle]
pub unsafe extern "C" fn win() {
    printf(b"Arbitrary access achieved!\n\0" as *const u8 as *const core::ffi::c_char);
}
static mut DB_FILE: *const core::ffi::c_char = b"enc.db\0" as *const u8
    as *const core::ffi::c_char;
static mut DB_MAGIC: [uint8_t; 8] = [
    'S' as i32 as uint8_t,
    'T' as i32 as uint8_t,
    'O' as i32 as uint8_t,
    'R' as i32 as uint8_t,
    'D' as i32 as uint8_t,
    'B' as i32 as uint8_t,
    '1' as i32 as uint8_t,
    '\n' as i32 as uint8_t,
];
static mut KDF_OPSLIMIT: core::ffi::c_ulonglong = crypto_pwhash_OPSLIMIT_INTERACTIVE
    as core::ffi::c_ulonglong;
static mut KDF_MEMLIMIT: size_t = crypto_pwhash_MEMLIMIT_INTERACTIVE as size_t;
static mut g_suppress_write_message: core::ffi::c_int = 0 as core::ffi::c_int;
unsafe extern "C" fn ensure_db_initialized(
    mut out_fp: *mut *mut FILE,
) -> core::ffi::c_int {
    let mut fp: *mut FILE = fopen(
        DB_FILE,
        b"r+b\0" as *const u8 as *const core::ffi::c_char,
    );
    if fp.is_null() {
        fp = fopen(DB_FILE, b"w+b\0" as *const u8 as *const core::ffi::c_char);
        if fp.is_null() {
            fprintf(
                stderr,
                b"Error: cannot open database\n\0" as *const u8
                    as *const core::ffi::c_char,
            );
            return -(1 as core::ffi::c_int);
        }
        if fwrite(
            DB_MAGIC.as_ptr() as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<[uint8_t; 8]>() as usize
        {
            fprintf(
                stderr,
                b"Error: cannot initialize database\n\0" as *const u8
                    as *const core::ffi::c_char,
            );
            fclose(fp);
            return -(1 as core::ffi::c_int);
        }
        fflush(fp);
        fsync(fileno(fp));
    } else {
        let mut magic: [uint8_t; 8] = [0; 8];
        if fread(
            magic.as_mut_ptr() as *mut core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<[uint8_t; 8]>() as usize
            || memcmp(
                magic.as_mut_ptr() as *const core::ffi::c_void,
                DB_MAGIC.as_ptr() as *const core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
            ) != 0 as core::ffi::c_int
        {
            fprintf(
                stderr,
                b"Error: invalid database format\n\0" as *const u8
                    as *const core::ffi::c_char,
            );
            fclose(fp);
            return -(1 as core::ffi::c_int);
        }
        fseek(fp, 0 as core::ffi::c_long, SEEK_END);
    }
    *out_fp = fp;
    return 0 as core::ffi::c_int;
}
unsafe extern "C" fn derive_user_key(
    mut token: *const core::ffi::c_char,
    mut salt: *const uint8_t,
    mut key: *mut uint8_t,
) -> core::ffi::c_int {
    if crypto_pwhash(
        key as *mut core::ffi::c_uchar,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES as core::ffi::c_ulonglong,
        token,
        strlen(token) as core::ffi::c_ulonglong,
        salt as *const core::ffi::c_uchar,
        KDF_OPSLIMIT,
        KDF_MEMLIMIT,
        crypto_pwhash_ALG_DEFAULT,
    ) != 0 as core::ffi::c_int
    {
        return -(1 as core::ffi::c_int);
    }
    return 0 as core::ffi::c_int;
}
unsafe extern "C" fn scan_for_user_auth(
    mut username: *const core::ffi::c_char,
    mut salt_out: *mut uint8_t,
    mut verify_out: *mut uint8_t,
) -> core::ffi::c_int {
    let mut fp: *mut FILE = fopen(
        DB_FILE,
        b"rb\0" as *const u8 as *const core::ffi::c_char,
    );
    if fp.is_null() {
        return -(1 as core::ffi::c_int);
    }
    let mut magic: [uint8_t; 8] = [0; 8];
    if fread(
        magic.as_mut_ptr() as *mut core::ffi::c_void,
        1 as size_t,
        ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
        fp,
    ) as usize != ::core::mem::size_of::<[uint8_t; 8]>() as usize
        || memcmp(
            magic.as_mut_ptr() as *const core::ffi::c_void,
            DB_MAGIC.as_ptr() as *const core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
        ) != 0 as core::ffi::c_int
    {
        fclose(fp);
        return -(1 as core::ffi::c_int);
    }
    let mut found: core::ffi::c_int = 0 as core::ffi::c_int;
    loop {
        let mut type_0: uint32_t = 0;
        if fread(
            &mut type_0 as *mut uint32_t as *mut core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        {
            break;
        }
        if type_0 == REC_REGISTER as core::ffi::c_int as uint32_t {
            let mut ulen: uint16_t = 0;
            if fread(
                &mut ulen as *mut uint16_t as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<uint16_t>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<uint16_t>() as usize
            {
                break;
            }
            if ulen as core::ffi::c_int > 4096 as core::ffi::c_int {
                break;
            }
            let mut uname: *mut core::ffi::c_char = malloc(
                (ulen as core::ffi::c_int + 1 as core::ffi::c_int) as size_t,
            ) as *mut core::ffi::c_char;
            if uname.is_null() {
                break;
            }
            if fread(uname as *mut core::ffi::c_void, 1 as size_t, ulen as size_t, fp)
                != ulen as core::ffi::c_ulong
            {
                free(uname as *mut core::ffi::c_void);
                break;
            } else {
                *uname.offset(ulen as isize) = '\0' as i32 as core::ffi::c_char;
                let mut salt: [uint8_t; 16] = [0; 16];
                if fread(
                    salt.as_mut_ptr() as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<[uint8_t; 16]>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<[uint8_t; 16]>() as usize
                {
                    free(uname as *mut core::ffi::c_void);
                    break;
                } else {
                    let mut verify: [uint8_t; 32] = [0; 32];
                    if fread(
                        verify.as_mut_ptr() as *mut core::ffi::c_void,
                        1 as size_t,
                        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
                        fp,
                    ) as usize != ::core::mem::size_of::<[uint8_t; 32]>() as usize
                    {
                        free(uname as *mut core::ffi::c_void);
                        break;
                    } else {
                        if strcmp(uname, username) == 0 as core::ffi::c_int {
                            memcpy(
                                salt_out as *mut core::ffi::c_void,
                                salt.as_mut_ptr() as *const core::ffi::c_void,
                                ::core::mem::size_of::<[uint8_t; 16]>() as size_t,
                            );
                            memcpy(
                                verify_out as *mut core::ffi::c_void,
                                verify.as_mut_ptr() as *const core::ffi::c_void,
                                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
                            );
                            found = 1 as core::ffi::c_int;
                        }
                        free(uname as *mut core::ffi::c_void);
                    }
                }
            }
        } else if type_0 == REC_WRITE as core::ffi::c_int as uint32_t {
            let mut meta_sizes: [uint32_t; 3] = [0; 3];
            if fread(
                meta_sizes.as_mut_ptr() as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<[uint32_t; 3]>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<[uint32_t; 3]>() as usize
            {
                break;
            }
            let mut skip: size_t = (meta_sizes[0 as core::ffi::c_int as usize] as size_t)
                .wrapping_add(meta_sizes[1 as core::ffi::c_int as usize] as size_t)
                .wrapping_add(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as size_t)
                .wrapping_add(meta_sizes[2 as core::ffi::c_int as usize] as size_t);
            if fseek(fp, skip as core::ffi::c_long, SEEK_CUR) != 0 as core::ffi::c_int {
                break;
            }
        } else if type_0 == REC_DELETE as core::ffi::c_int as uint32_t {
            let mut meta_sizes_0: [uint32_t; 2] = [0; 2];
            if fread(
                meta_sizes_0.as_mut_ptr() as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<[uint32_t; 2]>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<[uint32_t; 2]>() as usize
            {
                break;
            }
            if fseek(
                fp,
                (meta_sizes_0[0 as core::ffi::c_int as usize])
                    .wrapping_add(meta_sizes_0[1 as core::ffi::c_int as usize])
                    as core::ffi::c_long,
                SEEK_CUR,
            ) != 0 as core::ffi::c_int
            {
                break;
            }
        } else {
            if !(type_0 == REC_CREATE as core::ffi::c_int as uint32_t) {
                break;
            }
            let mut meta_sizes_1: [uint32_t; 2] = [0; 2];
            if fread(
                meta_sizes_1.as_mut_ptr() as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<[uint32_t; 2]>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<[uint32_t; 2]>() as usize
            {
                break;
            }
            if fseek(
                fp,
                (meta_sizes_1[0 as core::ffi::c_int as usize])
                    .wrapping_add(meta_sizes_1[1 as core::ffi::c_int as usize])
                    as core::ffi::c_long,
                SEEK_CUR,
            ) != 0 as core::ffi::c_int
            {
                break;
            }
        }
    }
    fclose(fp);
    return if found != 0 { 0 as core::ffi::c_int } else { -(1 as core::ffi::c_int) };
}
unsafe extern "C" fn cmd_register(
    mut username: *const core::ffi::c_char,
    mut token: *const core::ffi::c_char,
) -> core::ffi::c_int {
    if sodium_init() < 0 as core::ffi::c_int {
        fprintf(
            stderr,
            b"Error: crypto initialization failed\n\0" as *const u8
                as *const core::ffi::c_char,
        );
        return 1 as core::ffi::c_int;
    }
    let mut fp: *mut FILE = 0 as *mut FILE;
    if ensure_db_initialized(&mut fp) != 0 as core::ffi::c_int {
        return 1 as core::ffi::c_int;
    }
    let mut existing_salt: [uint8_t; 16] = [0; 16];
    let mut existing_verify: [uint8_t; 32] = [0; 32];
    if scan_for_user_auth(
        username,
        existing_salt.as_mut_ptr(),
        existing_verify.as_mut_ptr(),
    ) == 0 as core::ffi::c_int
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        fclose(fp);
        return 255 as core::ffi::c_int;
    }
    let mut salt: [uint8_t; 16] = [0; 16];
    randombytes_buf(
        salt.as_mut_ptr() as *mut core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 16]>() as size_t,
    );
    let mut key: [uint8_t; 32] = [0; 32];
    if crypto_pwhash(
        key.as_mut_ptr() as *mut core::ffi::c_uchar,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES as core::ffi::c_ulonglong,
        token,
        strlen(token) as core::ffi::c_ulonglong,
        salt.as_mut_ptr(),
        KDF_OPSLIMIT,
        KDF_MEMLIMIT,
        crypto_pwhash_ALG_DEFAULT,
    ) != 0 as core::ffi::c_int
    {
        fclose(fp);
        return 255 as core::ffi::c_int;
    }
    let mut verify: [uint8_t; 32] = [0; 32];
    let mut ct: *const core::ffi::c_char = b"stor-key-verify\0" as *const u8
        as *const core::ffi::c_char;
    crypto_generichash(
        verify.as_mut_ptr() as *mut core::ffi::c_uchar,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        ct as *const core::ffi::c_uchar,
        strlen(ct) as core::ffi::c_ulonglong,
        key.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    );
    sodium_memzero(
        key.as_mut_ptr() as *mut core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    );
    let mut type_0: uint32_t = REC_REGISTER as core::ffi::c_int as uint32_t;
    let mut ulen: uint16_t = strlen(username) as uint16_t;
    if fwrite(
        &mut type_0 as *mut uint32_t as *const core::ffi::c_void,
        1 as size_t,
        ::core::mem::size_of::<uint32_t>() as size_t,
        fp,
    ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            &mut ulen as *mut uint16_t as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint16_t>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<uint16_t>() as usize
        || fwrite(username as *const core::ffi::c_void, 1 as size_t, ulen as size_t, fp)
            != ulen as core::ffi::c_ulong
        || fwrite(
            salt.as_mut_ptr() as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<[uint8_t; 16]>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<[uint8_t; 16]>() as usize
        || fwrite(
            verify.as_mut_ptr() as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<[uint8_t; 32]>() as usize
    {
        fprintf(
            stderr,
            b"Error: registration failed\n\0" as *const u8 as *const core::ffi::c_char,
        );
        fclose(fp);
        return 1 as core::ffi::c_int;
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    printf(
        b"User '%s' has been registered\n\0" as *const u8 as *const core::ffi::c_char,
        username,
    );
    return 0 as core::ffi::c_int;
}
unsafe extern "C" fn cmd_write(
    mut username: *const core::ffi::c_char,
    mut token: *const core::ffi::c_char,
    mut filename: *const core::ffi::c_char,
    mut inputfile: *const core::ffi::c_char,
    mut text: *const core::ffi::c_char,
) -> core::ffi::c_int {
    if sodium_init() < 0 as core::ffi::c_int {
        fprintf(
            stderr,
            b"Error: crypto initialization failed\n\0" as *const u8
                as *const core::ffi::c_char,
        );
        return 1 as core::ffi::c_int;
    }
    let mut salt: [uint8_t; 16] = [0; 16];
    let mut verify_stored: [uint8_t; 32] = [0; 32];
    if scan_for_user_auth(username, salt.as_mut_ptr(), verify_stored.as_mut_ptr())
        != 0 as core::ffi::c_int
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut key: [uint8_t; 32] = [0; 32];
    if derive_user_key(token, salt.as_mut_ptr(), key.as_mut_ptr())
        != 0 as core::ffi::c_int
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut verify_now: [uint8_t; 32] = [0; 32];
    let mut ct2: *const core::ffi::c_char = b"stor-key-verify\0" as *const u8
        as *const core::ffi::c_char;
    crypto_generichash(
        verify_now.as_mut_ptr() as *mut core::ffi::c_uchar,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        ct2 as *const core::ffi::c_uchar,
        strlen(ct2) as core::ffi::c_ulonglong,
        key.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    );
    if sodium_memcmp(
        verify_now.as_mut_ptr() as *const core::ffi::c_void,
        verify_stored.as_mut_ptr() as *const core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    ) != 0 as core::ffi::c_int
    {
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut plaintext: *mut uint8_t = 0 as *mut uint8_t;
    let mut plen: size_t = 0 as size_t;
    if !inputfile.is_null() {
        let mut sf: *mut FILE = fopen(
            inputfile,
            b"rb\0" as *const u8 as *const core::ffi::c_char,
        );
        if sf.is_null() {
            fprintf(
                stderr,
                b"Error: cannot open input file\n\0" as *const u8
                    as *const core::ffi::c_char,
            );
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            return 1 as core::ffi::c_int;
        }
        fseek(sf, 0 as core::ffi::c_long, SEEK_END);
        let mut slen: core::ffi::c_long = ftell(sf);
        fseek(sf, 0 as core::ffi::c_long, SEEK_SET);
        plaintext = malloc(slen as size_t) as *mut uint8_t;
        if plaintext.is_null()
            || fread(
                plaintext as *mut core::ffi::c_void,
                1 as size_t,
                slen as size_t,
                sf,
            ) as size_t != slen as size_t
        {
            free(plaintext as *mut core::ffi::c_void);
            fclose(sf);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            return 1 as core::ffi::c_int;
        }
        plen = slen as size_t;
        fclose(sf);
    } else if !text.is_null() {
        plen = strlen(text);
        plaintext = malloc(plen) as *mut uint8_t;
        if plaintext.is_null() {
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            return 1 as core::ffi::c_int;
        }
        memcpy(
            plaintext as *mut core::ffi::c_void,
            text as *const core::ffi::c_void,
            plen,
        );
    } else {
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut nonce: [uint8_t; 24] = [0; 24];
    randombytes_buf(
        nonce.as_mut_ptr() as *mut core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 24]>() as size_t,
    );
    let mut uname_len: size_t = strlen(username);
    let mut fname_len: size_t = strlen(filename);
    let mut aad_len: size_t = uname_len
        .wrapping_add(1 as size_t)
        .wrapping_add(fname_len);
    let mut aad: *mut uint8_t = malloc(aad_len) as *mut uint8_t;
    if aad.is_null() {
        free(plaintext as *mut core::ffi::c_void);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 1 as core::ffi::c_int;
    }
    memcpy(
        aad as *mut core::ffi::c_void,
        username as *const core::ffi::c_void,
        uname_len,
    );
    *aad.offset(uname_len as isize) = 0 as uint8_t;
    memcpy(
        aad.offset(uname_len as isize).offset(1 as core::ffi::c_int as isize)
            as *mut core::ffi::c_void,
        filename as *const core::ffi::c_void,
        fname_len,
    );
    let mut ciph_len: size_t = plen
        .wrapping_add(crypto_aead_xchacha20poly1305_ietf_ABYTES as size_t);
    let mut ciphertext: *mut uint8_t = malloc(ciph_len) as *mut uint8_t;
    if ciphertext.is_null() {
        free(plaintext as *mut core::ffi::c_void);
        free(aad as *mut core::ffi::c_void);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 1 as core::ffi::c_int;
    }
    let mut out_len: core::ffi::c_ulonglong = 0 as core::ffi::c_ulonglong;
    if crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext as *mut core::ffi::c_uchar,
        &mut out_len,
        plaintext,
        plen as core::ffi::c_ulonglong,
        aad,
        aad_len as core::ffi::c_ulonglong,
        0 as *const core::ffi::c_uchar,
        nonce.as_mut_ptr(),
        key.as_mut_ptr(),
    ) != 0 as core::ffi::c_int
    {
        free(plaintext as *mut core::ffi::c_void);
        free(ciphertext as *mut core::ffi::c_void);
        free(aad as *mut core::ffi::c_void);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 1 as core::ffi::c_int;
    }
    free(plaintext as *mut core::ffi::c_void);
    free(aad as *mut core::ffi::c_void);
    let mut fp: *mut FILE = 0 as *mut FILE;
    if ensure_db_initialized(&mut fp) != 0 as core::ffi::c_int {
        free(ciphertext as *mut core::ffi::c_void);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut type_0: uint32_t = REC_WRITE as core::ffi::c_int as uint32_t;
    let mut ulen: uint32_t = uname_len as uint32_t;
    let mut flen: uint32_t = fname_len as uint32_t;
    let mut clen: uint32_t = out_len as uint32_t;
    if fwrite(
        &mut type_0 as *mut uint32_t as *const core::ffi::c_void,
        1 as size_t,
        ::core::mem::size_of::<uint32_t>() as size_t,
        fp,
    ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            &mut ulen as *mut uint32_t as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            &mut flen as *mut uint32_t as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            &mut clen as *mut uint32_t as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(username as *const core::ffi::c_void, 1 as size_t, ulen as size_t, fp)
            != ulen as core::ffi::c_ulong
        || fwrite(filename as *const core::ffi::c_void, 1 as size_t, flen as size_t, fp)
            != flen as core::ffi::c_ulong
        || fwrite(
            nonce.as_mut_ptr() as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<[uint8_t; 24]>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<[uint8_t; 24]>() as usize
        || fwrite(
            ciphertext as *const core::ffi::c_void,
            1 as size_t,
            clen as size_t,
            fp,
        ) != clen as core::ffi::c_ulong
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        fclose(fp);
        free(ciphertext as *mut core::ffi::c_void);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 255 as core::ffi::c_int;
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    free(ciphertext as *mut core::ffi::c_void);
    sodium_memzero(
        key.as_mut_ptr() as *mut core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    );
    if g_suppress_write_message == 0 {
        printf(
            b"Data written to file '%s' by user '%s'\n\0" as *const u8
                as *const core::ffi::c_char,
            filename,
            username,
        );
    }
    return 0 as core::ffi::c_int;
}
unsafe extern "C" fn cmd_read(
    mut username: *const core::ffi::c_char,
    mut token: *const core::ffi::c_char,
    mut filename: *const core::ffi::c_char,
    mut outputfile: *const core::ffi::c_char,
) -> core::ffi::c_int {
    if sodium_init() < 0 as core::ffi::c_int {
        fprintf(
            stderr,
            b"Error: crypto initialization failed\n\0" as *const u8
                as *const core::ffi::c_char,
        );
        return 1 as core::ffi::c_int;
    }
    let mut salt: [uint8_t; 16] = [0; 16];
    let mut verify_stored: [uint8_t; 32] = [0; 32];
    if scan_for_user_auth(username, salt.as_mut_ptr(), verify_stored.as_mut_ptr())
        != 0 as core::ffi::c_int
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut key: [uint8_t; 32] = [0; 32];
    if derive_user_key(token, salt.as_mut_ptr(), key.as_mut_ptr())
        != 0 as core::ffi::c_int
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut verify_now: [uint8_t; 32] = [0; 32];
    let mut ct3: *const core::ffi::c_char = b"stor-key-verify\0" as *const u8
        as *const core::ffi::c_char;
    crypto_generichash(
        verify_now.as_mut_ptr() as *mut core::ffi::c_uchar,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        ct3 as *const core::ffi::c_uchar,
        strlen(ct3) as core::ffi::c_ulonglong,
        key.as_mut_ptr(),
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    );
    if sodium_memcmp(
        verify_now.as_mut_ptr() as *const core::ffi::c_void,
        verify_stored.as_mut_ptr() as *const core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    ) != 0 as core::ffi::c_int
    {
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut fp: *mut FILE = fopen(
        DB_FILE,
        b"rb\0" as *const u8 as *const core::ffi::c_char,
    );
    if fp.is_null() {
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 1 as core::ffi::c_int;
    }
    let mut magic: [uint8_t; 8] = [0; 8];
    if fread(
        magic.as_mut_ptr() as *mut core::ffi::c_void,
        1 as size_t,
        ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
        fp,
    ) as usize != ::core::mem::size_of::<[uint8_t; 8]>() as usize
        || memcmp(
            magic.as_mut_ptr() as *const core::ffi::c_void,
            DB_MAGIC.as_ptr() as *const core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
        ) != 0 as core::ffi::c_int
    {
        fclose(fp);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 0 as core::ffi::c_int;
    }
    let mut segs: *mut seg_t = 0 as *mut seg_t;
    let mut seg_count: size_t = 0 as size_t;
    let mut seg_cap: size_t = 0 as size_t;
    loop {
        let mut type_0: uint32_t = 0;
        if fread(
            &mut type_0 as *mut uint32_t as *mut core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            fp,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        {
            break;
        }
        if type_0 == REC_REGISTER as core::ffi::c_int as uint32_t {
            let mut ulen: uint16_t = 0;
            if fread(
                &mut ulen as *mut uint16_t as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<uint16_t>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<uint16_t>() as usize
            {
                break;
            }
            if fseek(
                fp,
                (ulen as core::ffi::c_uint)
                    .wrapping_add(crypto_pwhash_SALTBYTES)
                    .wrapping_add(crypto_generichash_BYTES) as core::ffi::c_long,
                SEEK_CUR,
            ) != 0 as core::ffi::c_int
            {
                break;
            }
        } else if type_0 == REC_WRITE as core::ffi::c_int as uint32_t {
            let mut ulen_0: uint32_t = 0;
            let mut flen: uint32_t = 0;
            let mut clen: uint32_t = 0;
            if fread(
                &mut ulen_0 as *mut uint32_t as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<uint32_t>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                || fread(
                    &mut flen as *mut uint32_t as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<uint32_t>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                || fread(
                    &mut clen as *mut uint32_t as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<uint32_t>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<uint32_t>() as usize
            {
                break;
            }
            let mut uname: *mut core::ffi::c_char = malloc(
                ulen_0.wrapping_add(1 as uint32_t) as size_t,
            ) as *mut core::ffi::c_char;
            let mut fname: *mut core::ffi::c_char = malloc(
                flen.wrapping_add(1 as uint32_t) as size_t,
            ) as *mut core::ffi::c_char;
            if uname.is_null() || fname.is_null() {
                free(uname as *mut core::ffi::c_void);
                free(fname as *mut core::ffi::c_void);
                break;
            } else if fread(
                uname as *mut core::ffi::c_void,
                1 as size_t,
                ulen_0 as size_t,
                fp,
            ) != ulen_0 as core::ffi::c_ulong
                || fread(
                    fname as *mut core::ffi::c_void,
                    1 as size_t,
                    flen as size_t,
                    fp,
                ) != flen as core::ffi::c_ulong
            {
                free(uname as *mut core::ffi::c_void);
                free(fname as *mut core::ffi::c_void);
                break;
            } else {
                *uname.offset(ulen_0 as isize) = '\0' as i32 as core::ffi::c_char;
                *fname.offset(flen as isize) = '\0' as i32 as core::ffi::c_char;
                let mut nonce: [uint8_t; 24] = [0; 24];
                if fread(
                    nonce.as_mut_ptr() as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<[uint8_t; 24]>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<[uint8_t; 24]>() as usize
                {
                    free(uname as *mut core::ffi::c_void);
                    free(fname as *mut core::ffi::c_void);
                    break;
                } else {
                    let mut pos_cipher: core::ffi::c_long = ftell(fp);
                    if strcmp(uname, username) == 0 as core::ffi::c_int
                        && strcmp(fname, filename) == 0 as core::ffi::c_int
                    {
                        if seg_count == seg_cap {
                            let mut ncap: size_t = if seg_cap != 0 {
                                seg_cap.wrapping_mul(2 as size_t)
                            } else {
                                4 as size_t
                            };
                            let mut tmp: *mut seg_t = realloc(
                                segs as *mut core::ffi::c_void,
                                ncap.wrapping_mul(::core::mem::size_of::<seg_t>() as size_t),
                            ) as *mut seg_t;
                            if tmp.is_null() {
                                free(uname as *mut core::ffi::c_void);
                                free(fname as *mut core::ffi::c_void);
                                break;
                            } else {
                                segs = tmp;
                                seg_cap = ncap;
                            }
                        }
                        (*segs.offset(seg_count as isize)).pos = pos_cipher;
                        (*segs.offset(seg_count as isize)).clen = clen;
                        memcpy(
                            ((*segs.offset(seg_count as isize)).nonce).as_mut_ptr()
                                as *mut core::ffi::c_void,
                            nonce.as_mut_ptr() as *const core::ffi::c_void,
                            ::core::mem::size_of::<[uint8_t; 24]>() as size_t,
                        );
                        seg_count = seg_count.wrapping_add(1);
                    }
                    if fseek(fp, clen as core::ffi::c_long, SEEK_CUR)
                        != 0 as core::ffi::c_int
                    {
                        free(uname as *mut core::ffi::c_void);
                        free(fname as *mut core::ffi::c_void);
                        break;
                    } else {
                        free(uname as *mut core::ffi::c_void);
                        free(fname as *mut core::ffi::c_void);
                    }
                }
            }
        } else if type_0 == REC_DELETE as core::ffi::c_int as uint32_t {
            let mut ulen_1: uint32_t = 0;
            let mut flen_0: uint32_t = 0;
            if fread(
                &mut ulen_1 as *mut uint32_t as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<uint32_t>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                || fread(
                    &mut flen_0 as *mut uint32_t as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<uint32_t>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<uint32_t>() as usize
            {
                break;
            }
            if fseek(fp, ulen_1.wrapping_add(flen_0) as core::ffi::c_long, SEEK_CUR)
                != 0 as core::ffi::c_int
            {
                break;
            }
        } else {
            if !(type_0 == REC_CREATE as core::ffi::c_int as uint32_t) {
                break;
            }
            let mut ulen_2: uint32_t = 0;
            let mut flen_1: uint32_t = 0;
            if fread(
                &mut ulen_2 as *mut uint32_t as *mut core::ffi::c_void,
                1 as size_t,
                ::core::mem::size_of::<uint32_t>() as size_t,
                fp,
            ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                || fread(
                    &mut flen_1 as *mut uint32_t as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<uint32_t>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<uint32_t>() as usize
            {
                break;
            }
            if fseek(fp, ulen_2.wrapping_add(flen_1) as core::ffi::c_long, SEEK_CUR)
                != 0 as core::ffi::c_int
            {
                break;
            }
        }
    }
    if seg_count == 0 as size_t {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        fclose(fp);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        return 255 as core::ffi::c_int;
    }
    let mut uname_len: size_t = strlen(username);
    let mut fname_len: size_t = strlen(filename);
    let mut aad_len: size_t = uname_len
        .wrapping_add(1 as size_t)
        .wrapping_add(fname_len);
    let mut aad: *mut uint8_t = malloc(aad_len) as *mut uint8_t;
    if aad.is_null() {
        fclose(fp);
        sodium_memzero(
            key.as_mut_ptr() as *mut core::ffi::c_void,
            ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
        );
        free(segs as *mut core::ffi::c_void);
        return 255 as core::ffi::c_int;
    }
    memcpy(
        aad as *mut core::ffi::c_void,
        username as *const core::ffi::c_void,
        uname_len,
    );
    *aad.offset(uname_len as isize) = 0 as uint8_t;
    memcpy(
        aad.offset(uname_len as isize).offset(1 as core::ffi::c_int as isize)
            as *mut core::ffi::c_void,
        filename as *const core::ffi::c_void,
        fname_len,
    );
    let mut out: *mut uint8_t = 0 as *mut uint8_t;
    let mut out_len: size_t = 0 as size_t;
    let mut i: size_t = 0 as size_t;
    while i < seg_count {
        if fseek(fp, (*segs.offset(i as isize)).pos, SEEK_SET) != 0 as core::ffi::c_int {
            free(aad as *mut core::ffi::c_void);
            free(segs as *mut core::ffi::c_void);
            fclose(fp);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        let mut ciphertext: *mut uint8_t = malloc(
            (*segs.offset(i as isize)).clen as size_t,
        ) as *mut uint8_t;
        if ciphertext.is_null()
            || fread(
                ciphertext as *mut core::ffi::c_void,
                1 as size_t,
                (*segs.offset(i as isize)).clen as size_t,
                fp,
            ) != (*segs.offset(i as isize)).clen as core::ffi::c_ulong
        {
            free(ciphertext as *mut core::ffi::c_void);
            free(aad as *mut core::ffi::c_void);
            free(segs as *mut core::ffi::c_void);
            fclose(fp);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        let mut ptext_len: core::ffi::c_ulonglong = ((*segs.offset(i as isize)).clen)
            .wrapping_sub(crypto_aead_xchacha20poly1305_ietf_ABYTES as uint32_t)
            as core::ffi::c_ulonglong;
        let mut plaintext: *mut uint8_t = malloc(ptext_len as size_t) as *mut uint8_t;
        if plaintext.is_null() {
            free(ciphertext as *mut core::ffi::c_void);
            free(aad as *mut core::ffi::c_void);
            free(segs as *mut core::ffi::c_void);
            fclose(fp);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        if crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext as *mut core::ffi::c_uchar,
            &mut ptext_len,
            0 as *mut core::ffi::c_uchar,
            ciphertext,
            (*segs.offset(i as isize)).clen as core::ffi::c_ulonglong,
            aad,
            aad_len as core::ffi::c_ulonglong,
            ((*segs.offset(i as isize)).nonce).as_mut_ptr(),
            key.as_mut_ptr(),
        ) != 0 as core::ffi::c_int
        {
            free(ciphertext as *mut core::ffi::c_void);
            free(plaintext as *mut core::ffi::c_void);
            free(aad as *mut core::ffi::c_void);
            free(segs as *mut core::ffi::c_void);
            fclose(fp);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        free(ciphertext as *mut core::ffi::c_void);
        let mut tmp_0: *mut uint8_t = realloc(
            out as *mut core::ffi::c_void,
            out_len.wrapping_add(ptext_len as size_t),
        ) as *mut uint8_t;
        if tmp_0.is_null() {
            free(plaintext as *mut core::ffi::c_void);
            free(aad as *mut core::ffi::c_void);
            free(segs as *mut core::ffi::c_void);
            fclose(fp);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        out = tmp_0;
        memcpy(
            out.offset(out_len as isize) as *mut core::ffi::c_void,
            plaintext as *const core::ffi::c_void,
            ptext_len as size_t,
        );
        out_len = (out_len as core::ffi::c_ulong)
            .wrapping_add(ptext_len as size_t as core::ffi::c_ulong) as size_t as size_t;
        free(plaintext as *mut core::ffi::c_void);
        i = i.wrapping_add(1);
    }
    free(segs as *mut core::ffi::c_void);
    fclose(fp);
    free(aad as *mut core::ffi::c_void);
    if !outputfile.is_null() {
        let mut of: *mut FILE = fopen(
            outputfile,
            b"wb\0" as *const u8 as *const core::ffi::c_char,
        );
        if of.is_null()
            || fwrite(out as *const core::ffi::c_void, 1 as size_t, out_len, of)
                as size_t != out_len
        {
            if !of.is_null() {
                fclose(of);
            }
            free(out as *mut core::ffi::c_void);
            sodium_memzero(
                key.as_mut_ptr() as *mut core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
            );
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        fclose(of);
    } else {
        fwrite(out as *const core::ffi::c_void, 1 as size_t, out_len, stdout);
    }
    free(out as *mut core::ffi::c_void);
    sodium_memzero(
        key.as_mut_ptr() as *mut core::ffi::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as size_t,
    );
    return 0 as core::ffi::c_int;
}
unsafe extern "C" fn cmd_create(
    mut username: *const core::ffi::c_char,
    mut token: *const core::ffi::c_char,
    mut filename: *const core::ffi::c_char,
) -> core::ffi::c_int {
    if sodium_init() < 0 as core::ffi::c_int {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut fp: *mut FILE = fopen(
        DB_FILE,
        b"rb\0" as *const u8 as *const core::ffi::c_char,
    );
    let mut exists: core::ffi::c_int = 0 as core::ffi::c_int;
    if !fp.is_null() {
        let mut magic: [uint8_t; 8] = [0; 8];
        if fread(
            magic.as_mut_ptr() as *mut core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
            fp,
        ) as usize == ::core::mem::size_of::<[uint8_t; 8]>() as usize
            && memcmp(
                magic.as_mut_ptr() as *const core::ffi::c_void,
                DB_MAGIC.as_ptr() as *const core::ffi::c_void,
                ::core::mem::size_of::<[uint8_t; 8]>() as size_t,
            ) == 0 as core::ffi::c_int
        {
            loop {
                let mut type_0: uint32_t = 0;
                if fread(
                    &mut type_0 as *mut uint32_t as *mut core::ffi::c_void,
                    1 as size_t,
                    ::core::mem::size_of::<uint32_t>() as size_t,
                    fp,
                ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                {
                    break;
                }
                if type_0 == REC_REGISTER as core::ffi::c_int as uint32_t {
                    let mut ulen: uint16_t = 0;
                    if fread(
                        &mut ulen as *mut uint16_t as *mut core::ffi::c_void,
                        1 as size_t,
                        ::core::mem::size_of::<uint16_t>() as size_t,
                        fp,
                    ) as usize != ::core::mem::size_of::<uint16_t>() as usize
                    {
                        break;
                    }
                    if fseek(
                        fp,
                        (ulen as core::ffi::c_uint)
                            .wrapping_add(crypto_pwhash_SALTBYTES)
                            .wrapping_add(crypto_generichash_BYTES) as core::ffi::c_long,
                        SEEK_CUR,
                    ) != 0 as core::ffi::c_int
                    {
                        break;
                    }
                } else if type_0 == REC_WRITE as core::ffi::c_int as uint32_t {
                    let mut ulen_0: uint32_t = 0;
                    let mut flen: uint32_t = 0;
                    let mut clen: uint32_t = 0;
                    if fread(
                        &mut ulen_0 as *mut uint32_t as *mut core::ffi::c_void,
                        1 as size_t,
                        ::core::mem::size_of::<uint32_t>() as size_t,
                        fp,
                    ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                        || fread(
                            &mut flen as *mut uint32_t as *mut core::ffi::c_void,
                            1 as size_t,
                            ::core::mem::size_of::<uint32_t>() as size_t,
                            fp,
                        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                        || fread(
                            &mut clen as *mut uint32_t as *mut core::ffi::c_void,
                            1 as size_t,
                            ::core::mem::size_of::<uint32_t>() as size_t,
                            fp,
                        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                    {
                        break;
                    }
                    let mut uname: *mut core::ffi::c_char = malloc(
                        ulen_0.wrapping_add(1 as uint32_t) as size_t,
                    ) as *mut core::ffi::c_char;
                    let mut fname: *mut core::ffi::c_char = malloc(
                        flen.wrapping_add(1 as uint32_t) as size_t,
                    ) as *mut core::ffi::c_char;
                    if uname.is_null() || fname.is_null() {
                        free(uname as *mut core::ffi::c_void);
                        free(fname as *mut core::ffi::c_void);
                        break;
                    } else if fread(
                        uname as *mut core::ffi::c_void,
                        1 as size_t,
                        ulen_0 as size_t,
                        fp,
                    ) != ulen_0 as core::ffi::c_ulong
                        || fread(
                            fname as *mut core::ffi::c_void,
                            1 as size_t,
                            flen as size_t,
                            fp,
                        ) != flen as core::ffi::c_ulong
                    {
                        free(uname as *mut core::ffi::c_void);
                        free(fname as *mut core::ffi::c_void);
                        break;
                    } else {
                        *uname.offset(ulen_0 as isize) = '\0' as i32
                            as core::ffi::c_char;
                        *fname.offset(flen as isize) = '\0' as i32 as core::ffi::c_char;
                        if strcmp(uname, username) == 0 as core::ffi::c_int
                            && strcmp(fname, filename) == 0 as core::ffi::c_int
                        {
                            exists = 1 as core::ffi::c_int;
                            free(uname as *mut core::ffi::c_void);
                            free(fname as *mut core::ffi::c_void);
                            break;
                        } else if fseek(
                            fp,
                            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
                                as core::ffi::c_long + clen as core::ffi::c_long,
                            SEEK_CUR,
                        ) != 0 as core::ffi::c_int
                        {
                            free(uname as *mut core::ffi::c_void);
                            free(fname as *mut core::ffi::c_void);
                            break;
                        } else {
                            free(uname as *mut core::ffi::c_void);
                            free(fname as *mut core::ffi::c_void);
                        }
                    }
                } else if type_0 == REC_DELETE as core::ffi::c_int as uint32_t {
                    let mut ms: [uint32_t; 2] = [0; 2];
                    if fread(
                        ms.as_mut_ptr() as *mut core::ffi::c_void,
                        1 as size_t,
                        ::core::mem::size_of::<[uint32_t; 2]>() as size_t,
                        fp,
                    ) as usize != ::core::mem::size_of::<[uint32_t; 2]>() as usize
                    {
                        break;
                    }
                    if fseek(
                        fp,
                        (ms[0 as core::ffi::c_int as usize])
                            .wrapping_add(ms[1 as core::ffi::c_int as usize])
                            as core::ffi::c_long,
                        SEEK_CUR,
                    ) != 0 as core::ffi::c_int
                    {
                        break;
                    }
                } else {
                    if !(type_0 == REC_CREATE as core::ffi::c_int as uint32_t) {
                        break;
                    }
                    let mut ulen_1: uint32_t = 0;
                    let mut flen_0: uint32_t = 0;
                    if fread(
                        &mut ulen_1 as *mut uint32_t as *mut core::ffi::c_void,
                        1 as size_t,
                        ::core::mem::size_of::<uint32_t>() as size_t,
                        fp,
                    ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                        || fread(
                            &mut flen_0 as *mut uint32_t as *mut core::ffi::c_void,
                            1 as size_t,
                            ::core::mem::size_of::<uint32_t>() as size_t,
                            fp,
                        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
                    {
                        break;
                    }
                    let mut uname_0: *mut core::ffi::c_char = malloc(
                        ulen_1.wrapping_add(1 as uint32_t) as size_t,
                    ) as *mut core::ffi::c_char;
                    let mut fname_0: *mut core::ffi::c_char = malloc(
                        flen_0.wrapping_add(1 as uint32_t) as size_t,
                    ) as *mut core::ffi::c_char;
                    if uname_0.is_null() || fname_0.is_null() {
                        free(uname_0 as *mut core::ffi::c_void);
                        free(fname_0 as *mut core::ffi::c_void);
                        break;
                    } else if fread(
                        uname_0 as *mut core::ffi::c_void,
                        1 as size_t,
                        ulen_1 as size_t,
                        fp,
                    ) != ulen_1 as core::ffi::c_ulong
                        || fread(
                            fname_0 as *mut core::ffi::c_void,
                            1 as size_t,
                            flen_0 as size_t,
                            fp,
                        ) != flen_0 as core::ffi::c_ulong
                    {
                        free(uname_0 as *mut core::ffi::c_void);
                        free(fname_0 as *mut core::ffi::c_void);
                        break;
                    } else {
                        *uname_0.offset(ulen_1 as isize) = '\0' as i32
                            as core::ffi::c_char;
                        *fname_0.offset(flen_0 as isize) = '\0' as i32
                            as core::ffi::c_char;
                        if strcmp(uname_0, username) == 0 as core::ffi::c_int
                            && strcmp(fname_0, filename) == 0 as core::ffi::c_int
                        {
                            exists = 1 as core::ffi::c_int;
                            free(uname_0 as *mut core::ffi::c_void);
                            free(fname_0 as *mut core::ffi::c_void);
                            break;
                        } else {
                            free(uname_0 as *mut core::ffi::c_void);
                            free(fname_0 as *mut core::ffi::c_void);
                        }
                    }
                }
            }
        }
        fclose(fp);
    }
    if exists != 0 {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut wf: *mut FILE = 0 as *mut FILE;
    if ensure_db_initialized(&mut wf) != 0 as core::ffi::c_int {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut type_1: uint32_t = REC_CREATE as core::ffi::c_int as uint32_t;
    let mut ulen_2: uint32_t = strlen(username) as uint32_t;
    let mut flen_1: uint32_t = strlen(filename) as uint32_t;
    if fwrite(
        &mut type_1 as *mut uint32_t as *const core::ffi::c_void,
        1 as size_t,
        ::core::mem::size_of::<uint32_t>() as size_t,
        wf,
    ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            &mut ulen_2 as *mut uint32_t as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            wf,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            &mut flen_1 as *mut uint32_t as *const core::ffi::c_void,
            1 as size_t,
            ::core::mem::size_of::<uint32_t>() as size_t,
            wf,
        ) as usize != ::core::mem::size_of::<uint32_t>() as usize
        || fwrite(
            username as *const core::ffi::c_void,
            1 as size_t,
            ulen_2 as size_t,
            wf,
        ) != ulen_2 as core::ffi::c_ulong
        || fwrite(
            filename as *const core::ffi::c_void,
            1 as size_t,
            flen_1 as size_t,
            wf,
        ) != flen_1 as core::ffi::c_ulong
    {
        fclose(wf);
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    fflush(wf);
    fsync(fileno(wf));
    fclose(wf);
    printf(
        b"File '%s' has been created for user '%s'\n\0" as *const u8
            as *const core::ffi::c_char,
        filename,
        username,
    );
    return 0 as core::ffi::c_int;
}
unsafe fn main_0(
    mut argc: core::ffi::c_int,
    mut argv: *mut *mut core::ffi::c_char,
) -> core::ffi::c_int {
    optind = 1 as core::ffi::c_int;
    let mut username: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut token: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut filename: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut inputfile: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut outputfile: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut command: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut text: *mut core::ffi::c_char = 0 as *mut core::ffi::c_char;
    let mut opt: core::ffi::c_int = 0;
    let mut seen_username: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut seen_filename: core::ffi::c_int = 0 as core::ffi::c_int;
    let mut seen_key: core::ffi::c_int = 0 as core::ffi::c_int;
    loop {
        opt = getopt(
            argc,
            argv,
            b"u:k:f:i:o:\0" as *const u8 as *const core::ffi::c_char,
        );
        if !(opt != -(1 as core::ffi::c_int)) {
            break;
        }
        match opt {
            117 => {
                if seen_username != 0 {
                    printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
                    return 255 as core::ffi::c_int;
                }
                username = optarg;
                seen_username = 1 as core::ffi::c_int;
            }
            107 => {
                if seen_key != 0 {
                    printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
                    return 255 as core::ffi::c_int;
                }
                token = optarg;
                seen_key = 1 as core::ffi::c_int;
            }
            102 => {
                if seen_filename != 0 {
                    printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
                    return 255 as core::ffi::c_int;
                }
                filename = optarg;
                seen_filename = 1 as core::ffi::c_int;
            }
            105 => {
                inputfile = optarg;
            }
            111 => {
                outputfile = optarg;
            }
            _ => {
                printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
                return 255 as core::ffi::c_int;
            }
        }
    }
    if optind < argc {
        let fresh0 = optind;
        optind = optind + 1;
        command = *argv.offset(fresh0 as isize);
        if optind < argc {
            let fresh1 = optind;
            optind = optind + 1;
            text = *argv.offset(fresh1 as isize);
        }
        if optind < argc {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
    }
    if username.is_null() || command.is_null() {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    if *username.offset(0 as core::ffi::c_int as isize) as core::ffi::c_int
        == '\0' as i32
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    let mut p: *const core::ffi::c_char = username;
    while *p != 0 {
        if *p as core::ffi::c_int == ' ' as i32 || *p as core::ffi::c_int == '\t' as i32
            || *p as core::ffi::c_int == '\n' as i32
            || *p as core::ffi::c_int == '\r' as i32
        {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        p = p.offset(1);
    }
    if !filename.is_null()
        && *filename.offset(0 as core::ffi::c_int as isize) as core::ffi::c_int
            == '\0' as i32
    {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    }
    if strcmp(command, b"win\0" as *const u8 as *const core::ffi::c_char)
        == 0 as core::ffi::c_int
    {
        win();
        return 0 as core::ffi::c_int;
    }
    if strcmp(command, b"register\0" as *const u8 as *const core::ffi::c_char)
        == 0 as core::ffi::c_int
    {
        if token.is_null() {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        if !filename.is_null() || !inputfile.is_null() || !outputfile.is_null()
            || !text.is_null()
        {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        return cmd_register(username, token);
    } else if strcmp(command, b"create\0" as *const u8 as *const core::ffi::c_char)
        == 0 as core::ffi::c_int
    {
        if filename.is_null() {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        if !token.is_null() || !inputfile.is_null() || !outputfile.is_null()
            || !text.is_null()
        {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        return cmd_create(username, token, filename);
    } else if strcmp(command, b"write\0" as *const u8 as *const core::ffi::c_char)
        == 0 as core::ffi::c_int
    {
        if filename.is_null() || token.is_null() {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        let mut rest: core::ffi::c_int = argc - (optind + 1 as core::ffi::c_int);
        if !inputfile.is_null() {
            if rest > 0 as core::ffi::c_int {
                printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
                return 255 as core::ffi::c_int;
            }
        } else {
            if rest > 1 as core::ffi::c_int {
                printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
                return 255 as core::ffi::c_int;
            }
            if rest == 1 as core::ffi::c_int {
                text = *argv.offset((optind + 1 as core::ffi::c_int) as isize);
            }
        }
        return cmd_write(username, token, filename, inputfile, text);
    } else if strcmp(command, b"read\0" as *const u8 as *const core::ffi::c_char)
        == 0 as core::ffi::c_int
    {
        if filename.is_null() || token.is_null() {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        if !text.is_null() || !inputfile.is_null() {
            printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
            return 255 as core::ffi::c_int;
        }
        return cmd_read(username, token, filename, outputfile);
    } else {
        printf(b"invalid\n\0" as *const u8 as *const core::ffi::c_char);
        return 255 as core::ffi::c_int;
    };
}
pub fn main() {
    let mut args: Vec<*mut core::ffi::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as core::ffi::c_int,
                args.as_mut_ptr() as *mut *mut core::ffi::c_char,
            ) as i32,
        )
    }
}
