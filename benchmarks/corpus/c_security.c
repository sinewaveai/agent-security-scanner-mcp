// Benchmark corpus: C/C++ security vulnerabilities

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

// --- Buffer Overflow ---

// VULN: strcpy-usage
void unsafe_strcpy(char *dest, const char *src) {
    strcpy(dest, src);
}

// VULN: strcat-usage
void unsafe_strcat(char *dest, const char *src) {
    strcat(dest, src);
}

// VULN: gets-usage
void unsafe_gets(char *buffer) {
    gets(buffer);
}

// VULN: sprintf-usage
void unsafe_sprintf(char *buffer, const char *input) {
    sprintf(buffer, "Hello %s", input);
}

// VULN: vsprintf-usage
void unsafe_vsprintf(char *buffer, const char *format, va_list args) {
    vsprintf(buffer, format, args);
}

// VULN: scanf-usage
void unsafe_scanf(char *buffer) {
    scanf("%s", buffer);
}

// SAFE: strcpy-usage
void safe_strncpy(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n);
    dest[n-1] = '\0';
}

// SAFE: sprintf-usage
void safe_snprintf(char *buffer, size_t n, const char *input) {
    snprintf(buffer, n, "Hello %s", input);
}

// --- Format String ---

// VULN: format-string-printf
void unsafe_printf(const char *user_input) {
    printf(user_input);
}

// VULN: format-string-syslog
void unsafe_syslog(const char *user_input) {
    syslog(LOG_INFO, user_input);
}

// SAFE: format-string-printf
void safe_printf(const char *user_input) {
    printf("%s", user_input);
}

// --- Memory Safety ---

// VULN: use-after-free
void use_after_free() {
    char *ptr = malloc(100);
    free(ptr);
    strcpy(ptr, "data");  // Use after free!
}

// VULN: double-free
void double_free() {
    char *ptr = malloc(100);
    free(ptr);
    free(ptr);  // Double free!
}

// VULN: null-dereference
void null_deref(int *ptr) {
    *ptr = 42;  // Potential null dereference
}

// VULN: integer-overflow-malloc
void overflow_malloc(size_t n) {
    char *ptr = malloc(n * sizeof(int));  // Integer overflow
}

// SAFE: use-after-free
void safe_memory() {
    char *ptr = malloc(100);
    if (ptr) {
        strcpy(ptr, "data");
        free(ptr);
        ptr = NULL;
    }
}

// --- Command Injection ---

// VULN: system-usage
void unsafe_system(const char *user_input) {
    char cmd[256];
    sprintf(cmd, "cat %s", user_input);
    system(cmd);
}

// VULN: popen-usage
void unsafe_popen(const char *user_input) {
    char cmd[256];
    sprintf(cmd, "grep %s", user_input);
    popen(cmd, "r");
}

// SAFE: system-usage
void safe_exec() {
    execl("/bin/cat", "cat", "/etc/passwd", NULL);
}

// --- Weak Cryptography ---

// VULN: weak-hash-md5
void weak_md5(const char *data) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, strlen(data));
}

// VULN: weak-hash-sha1
void weak_sha1(const char *data) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, strlen(data));
}

// VULN: weak-cipher-des
void weak_des() {
    DES_key_schedule schedule;
    DES_set_key(&key, &schedule);
}

// VULN: ecb-mode
void weak_ecb() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
}

// SAFE: weak-hash-md5
void strong_hash(const char *data) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, strlen(data));
}

// --- Insecure Random ---

// VULN: weak-random
int weak_random() {
    return rand();
}

// SAFE: weak-random
int secure_random() {
    int r;
    getrandom(&r, sizeof(r), 0);
    return r;
}

// --- Other Issues ---

// VULN: strtok-usage
void unsafe_strtok(char *str) {
    char *token = strtok(str, ",");  // Not thread-safe
}

// VULN: insecure-memset
void insecure_clear(char *password) {
    memset(password, 0, strlen(password));  // May be optimized out
}

// VULN: hardcoded-password
const char *password = "SuperSecret123!";

// VULN: path-traversal
void unsafe_file_read(const char *user_path) {
    char path[256];
    sprintf(path, "/uploads/%s", user_path);
    FILE *f = fopen(path, "r");
}

// VULN: insecure-tempfile
void unsafe_tempfile() {
    char *filename = tmpnam(NULL);  // Race condition
    FILE *f = fopen(filename, "w");
}

// SAFE: insecure-tempfile
void safe_tempfile() {
    char template[] = "/tmp/fileXXXXXX";
    int fd = mkstemp(template);  // Secure temporary file
}

// SAFE: hardcoded-password
const char *get_password() {
    return getenv("DB_PASSWORD");
}

int main() {
    return 0;
}
