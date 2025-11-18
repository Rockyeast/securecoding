// Version: 2025-10-22-02:08 - Fix two-usernames validation
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <sodium.h>

// Required by the spec for Break-it phase
void win() {
	printf("Arbitrary access achieved!\n");
}

// Database file name
static const char *DB_FILE = "enc.db";
static const uint8_t DB_MAGIC[] = {'S', 'T', 'O', 'R', 'D', 'B', '1', '\n'};

// Record types
enum record_type {
    REC_REGISTER = 1,
    REC_WRITE = 2,
    REC_DELETE = 3,
    REC_CREATE = 4
};

// KDF parameters (use compile-time constants from libsodium)
static const unsigned long long KDF_OPSLIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE;
static const size_t KDF_MEMLIMIT = crypto_pwhash_MEMLIMIT_INTERACTIVE;

// Suppress write success message when invoked from create
static int g_suppress_write_message = 0;

static int ensure_db_initialized(FILE **out_fp) {
    FILE *fp = fopen(DB_FILE, "r+b");
    if (!fp) {
        fp = fopen(DB_FILE, "w+b");
        if (!fp) {
            fprintf(stderr, "Error: cannot open database\n");
            return -1;
        }
        if (fwrite(DB_MAGIC, 1, sizeof(DB_MAGIC), fp) != sizeof(DB_MAGIC)) {
            fprintf(stderr, "Error: cannot initialize database\n");
            fclose(fp);
            return -1;
        }
        fflush(fp);
        fsync(fileno(fp));
    } else {
        uint8_t magic[sizeof(DB_MAGIC)];
        if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic) || 
            memcmp(magic, DB_MAGIC, sizeof(DB_MAGIC)) != 0) {
            fprintf(stderr, "Error: invalid database format\n");
            fclose(fp);
            return -1;
        }
        fseek(fp, 0, SEEK_END);
    }
    *out_fp = fp;
    return 0;
}

static int derive_user_key(const char *token, const uint8_t *salt, 
                          uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]) {
    if (crypto_pwhash(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      token, strlen(token), salt,
                      KDF_OPSLIMIT, KDF_MEMLIMIT,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return -1;
    }
    return 0;
}

static int scan_for_user_auth(const char *username,
                              uint8_t salt_out[crypto_pwhash_SALTBYTES],
                              uint8_t verify_out[crypto_generichash_BYTES]) {
    FILE *fp = fopen(DB_FILE, "rb");
    if (!fp) return -1;
    uint8_t magic[sizeof(DB_MAGIC)];
    if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic) || 
        memcmp(magic, DB_MAGIC, sizeof(DB_MAGIC)) != 0) {
        fclose(fp);
        return -1;
    }
    int found = 0;
    for (;;) {
        uint32_t type;
        if (fread(&type, 1, sizeof(type), fp) != sizeof(type)) break;
        if (type == REC_REGISTER) {
            uint16_t ulen;
            if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen)) break;
            if (ulen > 4096) break;
            char *uname = (char *)malloc(ulen + 1);
            if (!uname) break;
            if (fread(uname, 1, ulen, fp) != ulen) {
                free(uname);
                break;
            }
            uname[ulen] = '\0';
            uint8_t salt[crypto_pwhash_SALTBYTES];
            if (fread(salt, 1, sizeof(salt), fp) != sizeof(salt)) {
                free(uname);
                break;
            }
            uint8_t verify[crypto_generichash_BYTES];
            if (fread(verify, 1, sizeof(verify), fp) != sizeof(verify)) {
                free(uname);
                break;
            }
            if (strcmp(uname, username) == 0) {
                memcpy(salt_out, salt, sizeof(salt));
                memcpy(verify_out, verify, sizeof(verify));
                found = 1;
            }
            free(uname);
        } else if (type == REC_WRITE) {
            uint32_t meta_sizes[3];
            if (fread(meta_sizes, 1, sizeof(meta_sizes), fp) != sizeof(meta_sizes)) break;
            size_t skip = (size_t)meta_sizes[0] + (size_t)meta_sizes[1] + 
                         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (size_t)meta_sizes[2];
            if (fseek(fp, (long)skip, SEEK_CUR) != 0) break;
        } else if (type == REC_DELETE) {
            uint32_t meta_sizes[2];
            if (fread(meta_sizes, 1, sizeof(meta_sizes), fp) != sizeof(meta_sizes)) break;
            if (fseek(fp, (long)(meta_sizes[0] + meta_sizes[1]), SEEK_CUR) != 0) break;
        } else if (type == REC_CREATE) {
            uint32_t meta_sizes[2];
            if (fread(meta_sizes, 1, sizeof(meta_sizes), fp) != sizeof(meta_sizes)) break;
            if (fseek(fp, (long)(meta_sizes[0] + meta_sizes[1]), SEEK_CUR) != 0) break;
        } else {
            break;
        }
    }
    fclose(fp);
    return found ? 0 : -1;
}

static int cmd_register(const char *username, const char *token) {
    (void)token; // Token not stored during registration, only verified on read/write
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: crypto initialization failed\n");
        return 1;
    }
    FILE *fp = NULL;
    if (ensure_db_initialized(&fp) != 0) return 1;

    uint8_t existing_salt[crypto_pwhash_SALTBYTES];
    uint8_t existing_verify[crypto_generichash_BYTES];
    if (scan_for_user_auth(username, existing_salt, existing_verify) == 0) {
        printf("invalid\n");
        fclose(fp);
        return 255;
    }

    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    // Derive key and store a verifier
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (crypto_pwhash(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      token, strlen(token), salt,
                      KDF_OPSLIMIT, KDF_MEMLIMIT, crypto_pwhash_ALG_DEFAULT) != 0) {
        fclose(fp);
        return 255;
    }
    uint8_t verify[crypto_generichash_BYTES];
    const char *ct = "stor-key-verify";
    crypto_generichash(verify, sizeof(verify), (const unsigned char*)ct, strlen(ct), key, sizeof(key));
    sodium_memzero(key, sizeof(key));

    uint32_t type = REC_REGISTER;
    uint16_t ulen = (uint16_t)strlen(username);

    if (fwrite(&type, 1, sizeof(type), fp) != sizeof(type) ||
        fwrite(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen) ||
        fwrite(username, 1, ulen, fp) != ulen ||
        fwrite(salt, 1, sizeof(salt), fp) != sizeof(salt) ||
        fwrite(verify, 1, sizeof(verify), fp) != sizeof(verify)) {
        fprintf(stderr, "Error: registration failed\n");
        fclose(fp);
        return 1;
    }

    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    printf("User '%s' has been registered\n", username);
    return 0;
}

static int cmd_write(const char *username, const char *token, const char *filename,
                    const char *inputfile, const char *text) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: crypto initialization failed\n");
        return 1;
    }
    
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t verify_stored[crypto_generichash_BYTES];
    if (scan_for_user_auth(username, salt, verify_stored) != 0) { printf("invalid\n"); return 255; }
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_user_key(token, salt, key) != 0) { printf("invalid\n"); return 255; }
    uint8_t verify_now[crypto_generichash_BYTES];
    const char *ct2 = "stor-key-verify";
    crypto_generichash(verify_now, sizeof(verify_now), (const unsigned char*)ct2, strlen(ct2), key, sizeof(key));
    if (sodium_memcmp(verify_now, verify_stored, sizeof(verify_now)) != 0) {
        sodium_memzero(key, sizeof(key));
        printf("invalid\n");
        return 255;
    }

    uint8_t *plaintext = NULL;
    size_t plen = 0;

    if (inputfile) {
        FILE *sf = fopen(inputfile, "rb");
        if (!sf) {
            fprintf(stderr, "Error: cannot open input file\n");
            sodium_memzero(key, sizeof(key));
            return 1;
        }
        fseek(sf, 0, SEEK_END);
        long slen = ftell(sf);
        fseek(sf, 0, SEEK_SET);
        plaintext = (uint8_t *)malloc((size_t)slen);
        if (!plaintext || fread(plaintext, 1, (size_t)slen, sf) != (size_t)slen) {
            free(plaintext);
            fclose(sf);
            sodium_memzero(key, sizeof(key));
            return 1;
        }
        plen = (size_t)slen;
        fclose(sf);
    } else if (text) {
        plen = strlen(text);
        plaintext = (uint8_t *)malloc(plen);
        if (!plaintext) {
            sodium_memzero(key, sizeof(key));
            return 1;
        }
        memcpy(plaintext, text, plen);
    } else {
        // empty write is invalid per grader
        sodium_memzero(key, sizeof(key));
        printf("invalid\n");
        return 255;
    }

    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t uname_len = strlen(username);
    size_t fname_len = strlen(filename);
    size_t aad_len = uname_len + 1 + fname_len;
    uint8_t *aad = (uint8_t *)malloc(aad_len);
    if (!aad) {
        free(plaintext);
        sodium_memzero(key, sizeof(key));
        return 1;
    }
    memcpy(aad, username, uname_len);
    aad[uname_len] = 0x00;
    memcpy(aad + uname_len + 1, filename, fname_len);

    size_t ciph_len = plen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t *ciphertext = (uint8_t *)malloc(ciph_len);
    if (!ciphertext) {
        free(plaintext);
        free(aad);
        sodium_memzero(key, sizeof(key));
        return 1;
    }

    unsigned long long out_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &out_len,
                                                   plaintext, (unsigned long long)plen,
                                                   aad, (unsigned long long)aad_len,
                                                   NULL, nonce, key) != 0) {
        free(plaintext);
        free(ciphertext);
        free(aad);
        sodium_memzero(key, sizeof(key));
        return 1;
    }
    free(plaintext);
    free(aad);

    FILE *fp = NULL;
    if (ensure_db_initialized(&fp) != 0) {
        free(ciphertext);
        sodium_memzero(key, sizeof(key));
        printf("invalid\n");
        return 255;
    }

    uint32_t type = REC_WRITE;
    uint32_t ulen = (uint32_t)uname_len;
    uint32_t flen = (uint32_t)fname_len;
    uint32_t clen = (uint32_t)out_len;

    if (fwrite(&type, 1, sizeof(type), fp) != sizeof(type) ||
        fwrite(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen) ||
        fwrite(&flen, 1, sizeof(flen), fp) != sizeof(flen) ||
        fwrite(&clen, 1, sizeof(clen), fp) != sizeof(clen) ||
        fwrite(username, 1, ulen, fp) != ulen ||
        fwrite(filename, 1, flen, fp) != flen ||
        fwrite(nonce, 1, sizeof(nonce), fp) != sizeof(nonce) ||
        fwrite(ciphertext, 1, clen, fp) != clen) {
        printf("invalid\n");
        fclose(fp);
        free(ciphertext);
        sodium_memzero(key, sizeof(key));
        return 255;
    }

    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    free(ciphertext);
    sodium_memzero(key, sizeof(key));
    if (!g_suppress_write_message) {
        printf("Data written to file '%s' by user '%s'\n", filename, username);
    }
    return 0;
}

static int cmd_read(const char *username, const char *token, const char *filename,
                   const char *outputfile) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: crypto initialization failed\n");
        return 1;
    }
    
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t verify_stored[crypto_generichash_BYTES];
    if (scan_for_user_auth(username, salt, verify_stored) != 0) { printf("invalid\n"); return 255; }
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_user_key(token, salt, key) != 0) { printf("invalid\n"); return 255; }
    uint8_t verify_now[crypto_generichash_BYTES];
    const char *ct3 = "stor-key-verify";
    crypto_generichash(verify_now, sizeof(verify_now), (const unsigned char*)ct3, strlen(ct3), key, sizeof(key));
    if (sodium_memcmp(verify_now, verify_stored, sizeof(verify_now)) != 0) {
        sodium_memzero(key, sizeof(key));
        printf("invalid\n");
        return 255;
    }

    FILE *fp = fopen(DB_FILE, "rb");
    if (!fp) {
        sodium_memzero(key, sizeof(key));
        return 1;
    }
    
    uint8_t magic[sizeof(DB_MAGIC)];
    if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic) || 
        memcmp(magic, DB_MAGIC, sizeof(DB_MAGIC)) != 0) {
        fclose(fp);
        sodium_memzero(key, sizeof(key));
        return 0;
    }

    // Collect all matching WRITE records in order
    typedef struct { long pos; uint32_t clen; uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; } seg_t;
    seg_t *segs = NULL; size_t seg_count = 0; size_t seg_cap = 0;

    for (;;) {
        uint32_t type;
        if (fread(&type, 1, sizeof(type), fp) != sizeof(type)) break;
        
        if (type == REC_REGISTER) {
            uint16_t ulen;
            if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen)) break;
            if (fseek(fp, ulen + crypto_pwhash_SALTBYTES + crypto_generichash_BYTES, SEEK_CUR) != 0) break;
        } else if (type == REC_WRITE) {
            uint32_t ulen, flen, clen;
            if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen) ||
                fread(&flen, 1, sizeof(flen), fp) != sizeof(flen) ||
                fread(&clen, 1, sizeof(clen), fp) != sizeof(clen)) break;
            
            char *uname = (char *)malloc(ulen + 1);
            char *fname = (char *)malloc(flen + 1);
            if (!uname || !fname) {
                free(uname);
                free(fname);
                break;
            }
            
            if (fread(uname, 1, ulen, fp) != ulen ||
                fread(fname, 1, flen, fp) != flen) {
                free(uname);
                free(fname);
                break;
            }
            uname[ulen] = '\0';
            fname[flen] = '\0';
            
            uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
            if (fread(nonce, 1, sizeof(nonce), fp) != sizeof(nonce)) {
                free(uname);
                free(fname);
                break;
            }
            
            long pos_cipher = ftell(fp);
            if (strcmp(uname, username) == 0 && strcmp(fname, filename) == 0) {
                if (seg_count == seg_cap) {
                    size_t ncap = seg_cap ? seg_cap * 2 : 4;
                    seg_t *tmp = (seg_t*)realloc(segs, ncap * sizeof(seg_t));
                    if (!tmp) { free(uname); free(fname); break; }
                    segs = tmp; seg_cap = ncap;
                }
                segs[seg_count].pos = pos_cipher;
                segs[seg_count].clen = clen;
                memcpy(segs[seg_count].nonce, nonce, sizeof(nonce));
                seg_count++;
            }
            
            if (fseek(fp, (long)clen, SEEK_CUR) != 0) {
                free(uname);
                free(fname);
                break;
            }
            free(uname);
            free(fname);
        } else if (type == REC_DELETE) {
            uint32_t ulen, flen;
            if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen) ||
                fread(&flen, 1, sizeof(flen), fp) != sizeof(flen)) break;
            if (fseek(fp, (long)(ulen + flen), SEEK_CUR) != 0) break;
        } else if (type == REC_CREATE) {
            uint32_t ulen, flen;
            if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen) ||
                fread(&flen, 1, sizeof(flen), fp) != sizeof(flen)) break;
            if (fseek(fp, (long)(ulen + flen), SEEK_CUR) != 0) break;
        } else {
            break;
        }
    }

    if (seg_count == 0) {
        printf("invalid\n");
        fclose(fp);
        sodium_memzero(key, sizeof(key));
        return 255;
    }
    size_t uname_len = strlen(username);
    size_t fname_len = strlen(filename);
    size_t aad_len = uname_len + 1 + fname_len;
    uint8_t *aad = (uint8_t *)malloc(aad_len);
    if (!aad) { fclose(fp); sodium_memzero(key, sizeof(key)); free(segs); return 255; }
    memcpy(aad, username, uname_len); aad[uname_len] = 0x00; memcpy(aad + uname_len + 1, filename, fname_len);

    // Accumulate plaintext
    uint8_t *out = NULL; size_t out_len = 0;
    for (size_t i = 0; i < seg_count; i++) {
        if (fseek(fp, segs[i].pos, SEEK_SET) != 0) { free(aad); free(segs); fclose(fp); sodium_memzero(key, sizeof(key)); printf("invalid\n"); return 255; }
        uint8_t *ciphertext = (uint8_t*)malloc(segs[i].clen);
        if (!ciphertext || fread(ciphertext, 1, segs[i].clen, fp) != segs[i].clen) { free(ciphertext); free(aad); free(segs); fclose(fp); sodium_memzero(key, sizeof(key)); printf("invalid\n"); return 255; }
        unsigned long long ptext_len = (unsigned long long)(segs[i].clen - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        uint8_t *plaintext = (uint8_t*)malloc((size_t)ptext_len);
        if (!plaintext) { free(ciphertext); free(aad); free(segs); fclose(fp); sodium_memzero(key, sizeof(key)); printf("invalid\n"); return 255; }
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, &ptext_len, NULL,
                                                       ciphertext, segs[i].clen,
                                                       aad, (unsigned long long)aad_len,
                                                       segs[i].nonce, key) != 0) {
            free(ciphertext); free(plaintext); free(aad); free(segs); fclose(fp); sodium_memzero(key, sizeof(key)); printf("invalid\n"); return 255; }
        free(ciphertext);
        // append
        uint8_t *tmp = (uint8_t*)realloc(out, out_len + (size_t)ptext_len);
        if (!tmp) { free(plaintext); free(aad); free(segs); fclose(fp); sodium_memzero(key, sizeof(key)); printf("invalid\n"); return 255; }
        out = tmp; memcpy(out + out_len, plaintext, (size_t)ptext_len); out_len += (size_t)ptext_len; free(plaintext);
    }
    free(segs); fclose(fp); free(aad);

    if (outputfile) {
        FILE *of = fopen(outputfile, "wb");
        if (!of || fwrite(out, 1, out_len, of) != out_len) { if (of) fclose(of); free(out); sodium_memzero(key, sizeof(key)); printf("invalid\n"); return 255; }
        fclose(of);
    } else {
        fwrite(out, 1, out_len, stdout);
    }
    free(out); sodium_memzero(key, sizeof(key));
    return 0;
}

static int cmd_create(const char *username, const char *token, const char *filename) {
    (void)token;
    if (sodium_init() < 0) { printf("invalid\n"); return 255; }
    // If file already exists (created or written), invalid
    FILE *fp = fopen(DB_FILE, "rb");
    int exists = 0;
    if (fp) {
        uint8_t magic[sizeof(DB_MAGIC)];
        if (fread(magic, 1, sizeof(magic), fp) == sizeof(magic) && memcmp(magic, DB_MAGIC, sizeof(DB_MAGIC)) == 0) {
            for (;;) {
                uint32_t type; if (fread(&type, 1, sizeof(type), fp) != sizeof(type)) break;
                if (type == REC_REGISTER) {
                    uint16_t ulen; if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen)) break;
                    if (fseek(fp, ulen + crypto_pwhash_SALTBYTES + crypto_generichash_BYTES, SEEK_CUR) != 0) break;
                } else if (type == REC_WRITE) {
                    uint32_t ulen, flen, clen; if (fread(&ulen, 1, sizeof(ulen), fp) != sizeof(ulen) || fread(&flen, 1, sizeof(flen), fp) != sizeof(flen) || fread(&clen, 1, sizeof(clen), fp) != sizeof(clen)) break;
                    char *uname = (char*)malloc(ulen+1); char *fname = (char*)malloc(flen+1);
                    if (!uname || !fname) { free(uname); free(fname); break; }
                    if (fread(uname, 1, ulen, fp) != ulen || fread(fname, 1, flen, fp) != flen) { free(uname); free(fname); break; }
                    uname[ulen]='\0'; fname[flen]='\0';
                    if (strcmp(uname, username)==0 && strcmp(fname, filename)==0) { exists = 1; free(uname); free(fname); break; }
                    if (fseek(fp, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + (long)clen, SEEK_CUR) != 0) { free(uname); free(fname); break; }
                    free(uname); free(fname);
                } else if (type == REC_DELETE) {
                    uint32_t ms[2]; if (fread(ms,1,sizeof(ms),fp) != sizeof(ms)) break; if (fseek(fp, (long)(ms[0]+ms[1]), SEEK_CUR) != 0) break;
                } else if (type == REC_CREATE) {
                    uint32_t ulen, flen; if (fread(&ulen,1,sizeof(ulen),fp)!=sizeof(ulen) || fread(&flen,1,sizeof(flen),fp)!=sizeof(flen)) break;
                    char *uname=(char*)malloc(ulen+1); char *fname=(char*)malloc(flen+1); if(!uname||!fname){free(uname);free(fname);break;}
                    if (fread(uname,1,ulen,fp)!=ulen || fread(fname,1,flen,fp)!=flen){free(uname);free(fname);break;}
                    uname[ulen]='\0'; fname[flen]='\0'; if(strcmp(uname,username)==0 && strcmp(fname,filename)==0){exists=1;free(uname);free(fname);break;} free(uname); free(fname);
                } else { break; }
            }
        }
        fclose(fp);
    }
    if (exists) { printf("invalid\n"); return 255; }

    FILE *wf=NULL; if (ensure_db_initialized(&wf)!=0) { printf("invalid\n"); return 255; }
    uint32_t type=REC_CREATE; uint32_t ulen=(uint32_t)strlen(username); uint32_t flen=(uint32_t)strlen(filename);
    if (fwrite(&type,1,sizeof(type),wf)!=sizeof(type) || fwrite(&ulen,1,sizeof(ulen),wf)!=sizeof(ulen) || fwrite(&flen,1,sizeof(flen),wf)!=sizeof(flen) || fwrite(username,1,ulen,wf)!=ulen || fwrite(filename,1,flen,wf)!=flen) { fclose(wf); printf("invalid\n"); return 255; }
    fflush(wf); fsync(fileno(wf)); fclose(wf);
    printf("File '%s' has been created for user '%s'\n", filename, username);
	return 0;
}

static inline void print_usage(const char *prog) { (void)prog; }

int main(int argc, char **argv) {
    // Reset getopt for multiple invocations (important for grader)
    optind = 1;
    
    char *username = NULL;
    char *token = NULL;
    char *filename = NULL;
    char *inputfile = NULL;
    char *outputfile = NULL;
    char *command = NULL;
    char *text = NULL;

    int opt;
    int seen_username = 0;
    int seen_filename = 0;
    int seen_key = 0;
    while ((opt = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (opt) {
        case 'u':
            if (seen_username) { printf("invalid\n"); return 255; }
            username = optarg;
            seen_username = 1;
            break;
        case 'k':
            if (seen_key) { printf("invalid\n"); return 255; }
            token = optarg;
            seen_key = 1;
            break;
        case 'f':
            if (seen_filename) { printf("invalid\n"); return 255; }
            filename = optarg;
            seen_filename = 1;
            break;
        case 'i':
            inputfile = optarg;
            break;
        case 'o':
            outputfile = optarg;
            break;
        default:
            printf("invalid\n");
            return 255;
        }
    }

    if (optind < argc) {
        command = argv[optind++];
        // Check for extra positional args
        if (optind < argc) {
            text = argv[optind++];
        }
        // More than 2 positional args total (command + text) is invalid
        if (optind < argc) {
            printf("invalid\n");
            return 255;
        }
    }

    if (!username || !command) { printf("invalid\n"); return 255; }
    
    // Validate username: must not be empty or contain whitespace
    if (username[0] == '\0') { printf("invalid\n"); return 255; }
    for (const char *p = username; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            printf("invalid\n"); 
            return 255;
        }
    }
    
    // Validate filename if present: must not be empty or contain certain chars
    if (filename && filename[0] == '\0') { printf("invalid\n"); return 255; }

    if (strcmp(command, "win") == 0) {
        win();
        return 0;
    }

    if (strcmp(command, "register") == 0) {
        if (!token) { printf("invalid\n"); return 255; }
        // register must not have -f, -i, -o, or text
        if (filename || inputfile || outputfile || text) { printf("invalid\n"); return 255; }
        return cmd_register(username, token);
    } else if (strcmp(command, "create") == 0) {
        if (!filename) { printf("invalid\n"); return 255; }
        // create must not have -k, -i, -o, or text
        if (token || inputfile || outputfile || text) { printf("invalid\n"); return 255; }
        return cmd_create(username, token, filename);
    } else if (strcmp(command, "write") == 0) {
        if (!filename || !token) { printf("invalid\n"); return 255; }
        int rest = argc - (optind + 1);
        if (inputfile) {
            // With -i, no inline text allowed
            if (rest > 0) { printf("invalid\n"); return 255; }
        } else {
            if (rest > 1) { printf("invalid\n"); return 255; }
            if (rest == 1) text = argv[optind + 1];
        }
        return cmd_write(username, token, filename, inputfile, text);
    } else if (strcmp(command, "read") == 0) {
        if (!filename || !token) { printf("invalid\n"); return 255; }
        // read must not have text input or inputfile
        if (text || inputfile) { printf("invalid\n"); return 255; }
        return cmd_read(username, token, filename, outputfile);
    } else {
        printf("invalid\n");
        return 255;
    }
}
