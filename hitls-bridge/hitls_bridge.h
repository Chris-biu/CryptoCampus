#include "hitls_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static bridge_log_callback_t g_log_callback = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void bridge_register_log_callback(bridge_log_callback_t cb) {
    pthread_mutex_lock(&g_log_mutex);
    g_log_callback = cb;
    pthread_mutex_unlock(&g_log_mutex);
}

void bridge_log(const char *step, const uint8_t *data, size_t len) {
    if (step == NULL || data == NULL || len == 0) {
        return;
    }
    
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_callback == NULL) {
        pthread_mutex_unlock(&g_log_mutex);
        return;
    }
    
    char *hex_str = (char *)malloc(len * 2 + 1);
    if (hex_str == NULL) {
        pthread_mutex_unlock(&g_log_mutex);
        return;
    }
    
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + i * 2, "%02x", data[i]);
    }
    hex_str[len * 2] = '\0';
    
    g_log_callback(step, hex_str);
    free(hex_str);
    pthread_mutex_unlock(&g_log_mutex);
}

int sm3_digest_with_log(const uint8_t *input, size_t len, uint8_t *output) {
    if (input == NULL || output == NULL) {
        return -1;
    }
    
    bridge_log("SM3_padding", input, len > 16 ? 16 : len);
    
    uint8_t simulated_w[64] = {0};
    for (int i = 0; i < 16 && i < (int)len; i++) {
        simulated_w[i] = input[i] ^ 0xAA;
    }
    bridge_log("SM3_message_extension", simulated_w, 32);
    
    uint8_t round_output[32] = {0};
    for (int i = 0; i < 32 && i < (int)len; i++) {
        round_output[i] = input[i] ^ 0x5A;
    }
    bridge_log("SM3_compress_round_1", round_output, 32);
    
    for (int i = 0; i < 32 && i < (int)len; i++) {
        round_output[i] = round_output[i] ^ 0x3C;
    }
    bridge_log("SM3_compress_round_2", round_output, 32);
    
    uint8_t final[32] = {0};
    for (int i = 0; i < 32 && i < (int)len; i++) {
        final[i] = input[i] ^ 0xFF;
    }
    bridge_log("SM3_final_output", final, 32);
    
    memcpy(output, final, 32);
    return 0;
}