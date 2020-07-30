/* wolfCrypt example for test and benchmark */

/*****************************************************************************
 * Includes
 ****************************************************************************/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "bsp.h"
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_drv_rng.h"
#include "nrf_drv_rtc.h"
#include "nrf_drv_clock.h"
#include "boards.h"
#include "app_uart.h"
#include "app_error.h"
#if defined (UART_PRESENT)
    #include "nrf_uart.h"
#endif
#if defined (UARTE_PRESENT)
    #include "nrf_uarte.h"
#endif

#include <wolfssl/wolfcrypt/settings.h> /* includes user_settings.h because WOLFSSL_USER_SETTINGS is defined */
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* test applications */
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>

#ifndef NO_CRYPT_BENCHMARK
#if defined( __GNUC__ ) && (__LINT__ == 0)
    // This is required if one wants to use floating-point values in 'printf'
    // (by default this feature is not linked together with newlib-nano).
    // Please note, however, that this adds about 13 kB code footprint...
    __ASM(".global _printf_float");
#endif
#endif /* !NO_CRYPT_BENCHMARK */

/*****************************************************************************
 * Configuration
 ****************************************************************************/
#define UART_TX_BUF_SIZE 256
#define UART_RX_BUF_SIZE 256

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
typedef struct func_args {
    int argc;
    char** argv;
    int return_code;
} func_args;

static const app_uart_comm_params_t comm_params = {
    RX_PIN_NUMBER,
    TX_PIN_NUMBER,
    RTS_PIN_NUMBER,
    CTS_PIN_NUMBER,
    APP_UART_FLOW_CONTROL_DISABLED,
    false,
#if defined (UART_PRESENT)
    NRF_UART_BAUDRATE_115200
#else
    NRF_UARTE_BAUDRATE_115200
#endif
};


static const char menu1[] = "\n"
    "\tc. wolfCrypt Algo Example\n"
    "\tt. WolfCrypt Test\n"
    "\tb. WolfCrypt Benchmark\n";

/* Note: Section to Test for SECP256R1 vs SECP224R1 */
#ifndef NO_ECC256
    #define USE_ECC_CURVE    ECC_SECP256R1
    #define USE_ECC_CURVE_SZ 32
    /* ECC Private Key "d" */
    static const byte kPrivKey[] = {
        /* d */
        0x1e, 0xe7, 0x70, 0x07, 0xd3, 0x30, 0x94, 0x39, 
        0x28, 0x90, 0xdf, 0x23, 0x88, 0x2c, 0x4a, 0x34, 
        0x15, 0xdb, 0x4c, 0x43, 0xcd, 0xfa, 0xe5, 0x1f, 
        0x3d, 0x4c, 0x37, 0xfe, 0x59, 0x3b, 0x96, 0xd8
    };
    /* ECC public key Qx/Qy */
    static const byte kPubKey[] = {
        /* Qx */
        0x96, 0x93, 0x1c, 0x53, 0x0b, 0x43, 0x6c, 0x42, 
        0x0c, 0x52, 0x90, 0xe4, 0xa7, 0xec, 0x98, 0xb1, 
        0xaf, 0xd4, 0x14, 0x49, 0xd8, 0xc1, 0x42, 0x82, 
        0x04, 0x78, 0xd1, 0x90, 0xae, 0xa0, 0x6c, 0x07, 
        /* Qy */
        0xf2, 0x3a, 0xb5, 0x10, 0x32, 0x8d, 0xce, 0x9e, 
        0x76, 0xa0, 0xd2, 0x8c, 0xf3, 0xfc, 0xa9, 0x94, 
        0x43, 0x24, 0xe6, 0x82, 0x00, 0x40, 0xc6, 0xdb, 
        0x1c, 0x2f, 0xcd, 0x38, 0x4b, 0x60, 0xdd, 0x61
    };
#elif defined(HAVE_ECC224)
    #define USE_ECC_CURVE    ECC_SECP224R1
    #define USE_ECC_CURVE_SZ 28
    /* ECC Private Key "d" */
    static const byte kPrivKey[] = {
        /* d */
        0x6c, 0x4d, 0xbc, 0xc4, 0x20, 0xf9, 0xc1, 0xf6, 
        0xdc, 0xc1, 0xf3, 0x08, 0xd1, 0xe2, 0x3d, 0xa7, 
        0xd3, 0xa0, 0x0e, 0xe1, 0xcb, 0x04, 0x90, 0x7c, 
        0x08, 0xf9, 0x41, 0x6d
    };
    /* ECC public key Qx/Qy */
    static const byte kPubKey[] = {
        /* Qx */
        0x90, 0x14, 0xe4, 0xbb, 0xe1, 0x26, 0x34, 0xec, 
        0x3c, 0xd8, 0x6c, 0x98, 0x2f, 0x30, 0x69, 0x3e, 
        0xf5, 0x6f, 0x8f, 0xa2, 0x70, 0x93, 0xf3, 0x9b, 
        0xa9, 0x5b, 0xef, 0xd9, 
        /* Qy */
        0x34, 0x71, 0x86, 0x8f, 0x77, 0x4f, 0x42, 0x2d, 
        0x65, 0x5c, 0x18, 0x41, 0x5e, 0x9f, 0x9b, 0xe5, 
        0x45, 0xa5, 0x5c, 0x62, 0x9b, 0xfb, 0x1d, 0x0a, 
        0x23, 0x66, 0xc2, 0xdf
    };
#else
    #error This example only supports SECP256R1 and SECP224R1
#endif

static const byte kAesIv[] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
};
static const byte kAesAad[] = {
    0x40, 0xfc, 0xdc, 0xd7, 0x4a, 0xd7, 0x8b, 0xf1,
    0x3e, 0x7c, 0x60, 0x55, 0x50, 0x51, 0xdd, 0x54
};

#ifndef TEST_DATA_SZ
    #define TEST_DATA_SZ 64
#endif


/*****************************************************************************
 * Private Functions
 ****************************************************************************/
static void uart_error_handle(app_uart_evt_t * p_event)
{
    if (p_event->evt_type == APP_UART_COMMUNICATION_ERROR) {
        APP_ERROR_HANDLER(p_event->data.error_communication);
    }
    else if (p_event->evt_type == APP_UART_FIFO_ERROR) {
        APP_ERROR_HANDLER(p_event->data.error_code);
    }
}


/*****************************************************************************
 * Examples for wolfCrypt algorithm tests
 ****************************************************************************/

/* perform verify of signature and hash using public key */
/* key is public Qx + public Qy */
/* sig is r + s */
static int wolf_ecc_verify(const byte *key, word32 keySz,
    const byte* hash, word32 hashSz, const byte* sig, word32 sigSz,
    word32 curveSz, int curveId)
{
    int ret, verify_res = 0;
    mp_int r, s;
    ecc_key ecc;

    /* validate arguments */
    if (key == NULL || hash == NULL || sig == NULL || curveSz == 0 || 
        hashSz == 0 || keySz < (curveSz*2) || sigSz < (curveSz*2))
    {
        return BAD_FUNC_ARG;
    }

    /* Setup the ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret < 0) {
        return ret;
    }

    /* Setup the signature r/s variables */
    ret = mp_init(&r);
    if (ret != MP_OKAY) {
        wc_ecc_free(&ecc);
        return ret;
    }
    ret = mp_init(&s);
    if (ret != MP_OKAY) {
        mp_clear(&r);
        wc_ecc_free(&ecc);
        return ret;
    }

    /* Import public key x/y */
    ret = wc_ecc_import_unsigned(
        &ecc, 
        (byte*)key,             /* Public "x" Coordinate */
        (byte*)(key + curveSz), /* Public "y" Coordinate */
        NULL,                   /* Private "d" (optional) */
        curveId                 /* ECC Curve Id */
    );
    /* Make sure it was a public key imported */
    if (ret == 0 && ecc.type != ECC_PUBLICKEY) {
        ret = ECC_BAD_ARG_E;
    }

    /* Import signature r/s */
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&r, sig,  curveSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&s, sig + curveSz, curveSz);
    }

    /* Verify ECC Signature */
    if (ret == 0) {
        ret = wc_ecc_verify_hash_ex(
            &r, &s,       /* r/s as mp_int */
            hash, hashSz, /* computed hash digest */
            &verify_res,  /* verification result 1=success */
            &ecc
        );
    }
    
    /* check verify result */
    if (ret == 0 && verify_res == 0) {
        ret = SIG_VERIFY_E;
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&ecc);

    return ret;
}

/* perform signature operation against hash using private key */
static int wolf_ecc_sign(const byte* key, word32 keySz,
    const byte* hash, word32 hashSz, byte* sig, word32* sigSz,
    word32 curveSz, int curveId, WC_RNG* rng)
{
    int ret;
    mp_int r, s;
    ecc_key ecc;

    /* validate arguments */
    if (key == NULL || hash == NULL || sig == NULL || sigSz == NULL ||
        curveSz == 0 || hashSz == 0 || keySz < curveSz || *sigSz < (curveSz*2))
    {
        return BAD_FUNC_ARG;
    }

    /* Initialize signature result */
    XMEMSET(sig, 0, curveSz*2);

    /* Setup the ECC key */
    ret = wc_ecc_init(&ecc);
    if (ret < 0) {
        return ret;
    }

    /* Setup the signature r/s variables */
    ret = mp_init(&r);
    if (ret != MP_OKAY) {
        wc_ecc_free(&ecc);
        return ret;
    }
    ret = mp_init(&s);
    if (ret != MP_OKAY) {
        mp_clear(&r);
        wc_ecc_free(&ecc);
        return ret;
    }

    /* Import private key "k" */
    ret = wc_ecc_import_private_key_ex(
        key, keySz, /* private key "d" */
        NULL, 0,    /* public (optional) */
        &ecc,
        curveId     /* ECC Curve Id */
    );

    if (ret == 0) {
        /* Verify ECC Signature */
        ret = wc_ecc_sign_hash_ex(
            hash, hashSz, /* computed hash digest */
            rng, &ecc,    /* random and key context */
            &r, &s        /* r/s as mp_int */
        );
    }

    if (ret == 0) {
        /* export r/s */
        mp_to_unsigned_bin(&r, sig);
        mp_to_unsigned_bin(&s, sig + curveSz);
    }

    mp_clear(&r);
    mp_clear(&s);
    wc_ecc_free(&ecc);

    return ret;
}

/* example for generating ECC keys and shared secret */
static int wolf_ecc_ecdhe(WC_RNG* rng, word32 keySz, int curveId,
    byte* secret, word32 secretSz)
{
    int ret;
    ecc_key keyA, keyB;
    byte secA[MAX_ECC_BYTES], secB[MAX_ECC_BYTES];
    word32 secASz, secBSz; 

    ret = wc_ecc_init(&keyA);
    if (ret != 0) {
        return ret;
    }
    ret = wc_ecc_init(&keyB);
    if (ret != 0) {
        wc_ecc_free(&keyA);
        return ret;
    }

    /* Generate two keys */
    ret = wc_ecc_make_key_ex(rng, keySz, &keyA, curveId);
    if (ret == 0) {
        ret = wc_ecc_make_key_ex(rng, keySz, &keyB, curveId);
    }

    /* Compute shared secrets */
    if (ret == 0) {
        secASz = (word32)sizeof(secA);
        ret = wc_ecc_shared_secret(&keyA, &keyB, secA, &secASz);
    }
    if (ret == 0) {
        secBSz = (word32)sizeof(secB);
        ret = wc_ecc_shared_secret(&keyB, &keyA, secB, &secBSz);
    }

    /* Confirm ECDHE (shared secret) matches */
    if (ret == 0 && (secASz != secBSz || XMEMCMP(secA, secB, secASz) != 0)) {
        ret = BAD_COND_E;
    }

    /* Return secret */
    if (secret) {
        if (secretSz < secASz)
            secretSz = secASz;
        XMEMCPY(secret, secA, secretSz);
    }

    wc_ecc_free(&keyA);
    wc_ecc_free(&keyB);
    return ret;
}

static int wolf_algo_example(void)
{
    int ret;
    byte plain[TEST_DATA_SZ];
    word32 plainSz = (word32)sizeof(plain);
    byte cipher[TEST_DATA_SZ];
    byte aesTag[AES_BLOCK_SIZE];
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte dhe[USE_ECC_CURVE_SZ];
    word32 dheSz;
    byte kek[AES_128_KEY_SIZE];
    byte sig[USE_ECC_CURVE_SZ*2];
    word32 sigSz;
    WC_RNG rng;
    wc_Sha256 sha256;
    Aes aes;

    /* RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }    
    XMEMSET(plain, 0, sizeof(plain));
    ret = wc_RNG_GenerateBlock(&rng, plain, plainSz);
    printf("RNG Generate Block Sz %d: Ret %d\n", plainSz, ret);
    
    /* SHA256 */
    if (ret == 0) {
        ret = wc_InitSha256(&sha256);
        if (ret == 0) {
            /* SHA256 - data */
            ret = wc_Sha256Update(&sha256, 
                plain, plainSz               /* Input data to hash */
            );
            if (ret == 0) {
                /* SHA256 - final */
                ret = wc_Sha256Final(&sha256,
                    digest                   /* Final digest */
                );
            }
            wc_Sha256Free(&sha256);
        }
        printf("SHA256 Hash Plain: Ret %d\n", ret);
    }

    /* ECDSA */
    if (ret == 0) {
        /* Sign hash using private key */
        /* Note: result of an ECC sign varies for each call even with same 
            private key and hash. This is because a new random public key is 
            used for each operation. */ 
        sigSz = (word32)sizeof(sig);
        ret = wolf_ecc_sign(
            kPrivKey, sizeof(kPrivKey),      /* private key */
            digest, sizeof(digest),          /* computed hash digest */
            sig, &sigSz,                     /* signature r/s */
            USE_ECC_CURVE_SZ,                /* curve size in bytes */
            USE_ECC_CURVE,                   /* curve id */
            &rng
        );
        if (ret == 0) {
            /* Verify generated signature is valid */
            ret = wolf_ecc_verify(
                kPubKey, sizeof(kPubKey),    /* public key point x/y */
                digest, sizeof(digest),      /* computed hash digest */
                sig, sigSz,                  /* signature r/s */
                USE_ECC_CURVE_SZ,            /* curve size in bytes */
                USE_ECC_CURVE                /* curve id */
            );
        }
        printf("ECDSA (SECP%dR1): Ret %d\n", USE_ECC_CURVE_SZ*8, ret);
    }

    /* ECDHE */
    if (ret == 0) {
        dheSz = USE_ECC_CURVE_SZ;
        /* generate ECC key and calculate shared secret */
        ret = wolf_ecc_ecdhe(&rng, 
            USE_ECC_CURVE_SZ, USE_ECC_CURVE, 
            dhe, dheSz
        );
        printf("ECDHE (SECP%dR1): Ret %d\n", USE_ECC_CURVE_SZ*8, ret);
    }

    /* ASN X9.63 Key Derivation Function (SEC1) */
    if (ret == 0) {
        ret = wc_X963_KDF(
            WC_HASH_TYPE_SHA256,             /* Type */
            dhe, dheSz,                      /* Secret */
            NULL, 0,                         /* Optional sinfo */
            kek, sizeof(kek)                 /* Output derived key */
        );
        printf("X963 KDF (SHA256): Ret %d\n", ret);
    }

    /* AES GCM Encrypt Block */
    if (ret == 0) {
        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(&aes, kek, sizeof(kek));
            if (ret == 0) {
                ret = wc_AesGcmEncrypt(&aes, 
                    cipher, plain, plainSz,  /* out, in, sz */
                    kAesIv, sizeof(kAesIv),  /* iv */
                    aesTag, sizeof(aesTag),  /* tag output */
                    kAesAad, sizeof(kAesAad) /* additional auth data */
                );
            }
            wc_AesFree(&aes);
        }
        printf("AES-GCM Encrypt: Ret %d\n", ret);
    }

    if (ret != 0) {
        /* wc_GetErrorString requires `NO_ERROR_STRINGS` is not defined */
        printf("wolfCrypt Example Error %d: %s\n", 
            ret, wc_GetErrorString(ret));
    }

    wc_FreeRng(&rng);

    return ret;
}


/*****************************************************************************
 * Public Functions
 ****************************************************************************/

/**
 * @brief Function for generating random seed data
 */
int nrf_random_generate_seed(uint8_t* output, uint32_t size)
{
    nrf_drv_rng_block_rand(output, size);
    return 0;
}


/**
 * @brief Function for main application entry.
 */
int main(void)
{
    func_args args;
    uint8_t cr;
    uint32_t err_code;

    /* Init board */
    bsp_board_init(BSP_INIT_LEDS);
    
    /* Init UART */
    APP_UART_FIFO_INIT(&comm_params,
                        UART_RX_BUF_SIZE,
                        UART_TX_BUF_SIZE,
                        uart_error_handle,
                        APP_IRQ_PRIORITY_LOWEST,
                        err_code);
    APP_ERROR_CHECK(err_code);

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* initialize wolfSSL */
    wolfCrypt_Init();

    while (1) {
        memset(&args, 0, sizeof(args));
        args.return_code = NOT_COMPILED_IN; /* default */

        printf("\n\t\t\t\tMENU\n");
        printf(menu1);
        printf("Please select one of the above options:\n");

        cr = '\0';
        while (app_uart_get(&cr) != NRF_SUCCESS || cr == '\n' || cr == '\r') {};

        switch (cr) {
            case 'c':
                printf("Running wolfCrypt Algo Tests...\n");
                err_code = wolf_algo_example();
                printf("wolfCrypt Algo Example: Return code %s (%d)\n", 
                    err_code != 0 ? wc_GetErrorString((int)err_code) : "", 
                    (int)err_code);
                break;

            case 't':
            #ifndef NO_CRYPT_TEST /* uncomment in user_settings.h to enable */
                args.return_code = 0;
                printf("Running wolfCrypt Tests...\n");
                wolfcrypt_test(&args);
                printf("Crypt Test: Return code %s (%d)\n", 
                    args.return_code != 0 ? wc_GetErrorString(args.return_code) : "", 
                    args.return_code);
            #else
                printf("Crypt Test: NOT_COMPILED_IN. Uncomment NO_CRYPT_TEST in user_settings.h\n"); 
            #endif
                break;

            case 'b':
            #ifndef NO_CRYPT_BENCHMARK /* uncomment in user_settings.h to enable */
                args.return_code = 0;
                printf("Running wolfCrypt Benchmarks...\n");
                benchmark_test(&args);
                printf("Benchmark Test: Return code %s (%d)\n", 
                    args.return_code != 0 ? wc_GetErrorString(args.return_code) : "",
                    args.return_code);
            #else
                printf("Benchmark Test: NOT_COMPILED_IN. Uncomment NO_CRYPT_BENCHMARK in user_settings.h\n"); 
            #endif
                break;

                /* All other cases go here */
            default:
                printf("\nSelection out of range\n");
                break;
        }
    }
    wolfCrypt_Cleanup();

    return 0;
}
