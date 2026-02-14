// Test file for C/C++ security rules
// Contains intentional vulnerabilities for testing

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

// Buffer Overflow - Dangerous Functions - should be detected
void vulnerable_string_ops(char *input) {
    char buffer[64];
    strcpy(buffer, input);           // Unsafe strcpy
    strcat(buffer, " appended");     // Unsafe strcat
    sprintf(buffer, "User: %s", input);  // Unsafe sprintf
    vsprintf(buffer, format, args);  // Unsafe vsprintf
    gets(buffer);                    // Extremely dangerous gets
}

// Format String Vulnerability - should be detected
void format_string_vuln(char *user_input) {
    printf(user_input);              // Format string bug
    fprintf(stderr, user_input);     // Format string bug
    syslog(LOG_INFO, user_input);    // Format string bug
}

// Memory Management Issues - should be detected
void memory_issues() {
    char *ptr = malloc(100);
    free(ptr);
    // ptr not set to NULL - use after free potential

    char *ptr2 = malloc(50);
    free(ptr2);
    free(ptr2);  // Double free

    // Integer overflow in malloc
    int count = get_user_count();
    char *data = malloc(count * sizeof(struct user));
}

// Unsafe scanf - should be detected
void unsafe_input() {
    char name[50];
    scanf("%s", name);      // No width limit
    fscanf(file, "%s", buf);
}

// Command Injection - should be detected
void run_command(char *user_cmd) {
    system(user_cmd);       // Command injection
    popen(user_cmd, "r");   // Command injection
}

// Weak Cryptography - should be detected
void weak_crypto() {
    MD5_CTX md5ctx;
    MD5_Init(&md5ctx);
    MD5_Update(&md5ctx, data, len);
    MD5_Final(digest, &md5ctx);

    SHA1_Init(&sha1ctx);
    SHA1(data, len, digest);

    DES_set_key(&key, &schedule);
    DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);

    EVP_aes_128_ecb();  // ECB mode
}

// Weak Random - should be detected
void insecure_random() {
    int token = rand();
    srand(time(NULL));
}

// Hardcoded Credentials - should be detected
void hardcoded_creds() {
    char *password = "secretpassword123";
    char *api_key = "AKIAIOSFODNN7EXAMPLE1234";
}

// Insecure memset (may be optimized away) - should be detected
void clear_sensitive(char *password) {
    memset(password, 0, strlen(password));
}

// Thread-unsafe functions - should be detected
void tokenize(char *str) {
    char *token = strtok(str, ",");
}

// Insecure temp file - should be detected
void create_temp() {
    char *name = mktemp("/tmp/fileXXXXXX");
    char *name2 = tmpnam(NULL);
}

// Path traversal - should be detected
void read_file(char *path) {
    FILE *f = fopen("../config/secrets.txt", "r");
}

// Unchecked return values - should be detected
void unchecked_io() {
    fread(buffer, 1, size, file);
    write(fd, data, len);
}

int main() {
    printf("Test file for C vulnerabilities\n");
    return 0;
}
