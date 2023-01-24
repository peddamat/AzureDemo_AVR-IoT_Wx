/**
 *
 * \file
 *
 * \brief This module implements TLS Server Certificate Installation.
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
INCLUDES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/argtable/argtable3.h"
#include "crypto_lib_api.h"
#include "driver/include/m2m_types.h"
#include "programmer.h"
#include "root_setup.h"
#include "tls_srv_sec.h"

extern void ListDirectoryContents(const char *pcDir, char *pcExt, char ***ppacFileList, uint32 *pu32ListSize);
extern sint8 TlsCertStoreWriteCertChain(const char *pcPrivKeyFile, const char *pcSrvCertFile, const char *pcCADirPath, uint8 *pu8TlsSrvSecBuff, uint32 *pu32SecSz, tenuWriteMode enuMode);
extern int ReadFileToBuffer(char *pcFileName, uint8 **ppu8FileData, uint32 *pu32FileSize);

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
MACROS
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#define STIRCMP(argvPtr, text) \
    (!_strnicmp((argvPtr), (text), strlen((text))))

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
DATA TYPES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

typedef enum {
    TLS_STORE_INVALID,
    TLS_STORE_FLASH,
    TLS_STORE_FW_IMG
} tenuTLSCertStoreType;

typedef enum {
    CMD_WRITE,
    CMD_READ
} tenuCmd;

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
GLOBALS
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

static uint8 gauFirmware[FLASH_4M_TOTAL_SZ];
static uint8 gau8TlsSrvSec[M2M_TLS_SERVER_FLASH_SIZE];

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
TLS STORE LOADING
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

static sint8 TlsCertStoreLoadFromFlash(uint8 u8PortNum) {
    sint8 s8Ret = M2M_ERR_FAIL;

    if (programmer_init(&u8PortNum, 0) == M2M_SUCCESS) {
        s8Ret = programmer_read(gau8TlsSrvSec, M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE);
        programmer_deinit();
    }
    return s8Ret;
}

static sint8 TlsCertStoreLoadFromFwImage(const char *pcFwFile) {
    FILE *fp;
    sint8 s8Ret = M2M_ERR_FAIL;

    fp = fopen(pcFwFile, "rb");
    if (fp) {
        fseek(fp, M2M_TLS_SERVER_FLASH_OFFSET, SEEK_SET);
        fread(gau8TlsSrvSec, 1, M2M_TLS_SERVER_FLASH_SIZE, fp);
        fclose(fp);
        s8Ret = M2M_SUCCESS;
    } else {
        printf("* Error opening firmware file: <%s>\n", pcFwFile);
    }
    return s8Ret;
}

sint8 TlsCertStoreLoad(const char *pcFwFile, uint8 port, uint8 *vflash) {
    tenuTLSCertStoreType enuStore = strcmp(pcFwFile, "") ? TLS_STORE_FW_IMG : TLS_STORE_FLASH;

    sint8 ret = M2M_ERR_FAIL;
    switch (enuStore) {
        case TLS_STORE_FLASH:
            ret = TlsCertStoreLoadFromFlash(port);
            break;

        case TLS_STORE_FW_IMG:
            ret = TlsCertStoreLoadFromFwImage(pcFwFile);
            break;

        default:
            break;
    }

    if (ret == M2M_SUCCESS) {
        printf("TLS Certificate Store Loaded Successfully From: %s\n", (enuStore == TLS_STORE_FLASH) ? "Flash" : "Firmware Image");
    } else {
        printf("TLS Certificate Store Load FAILED From %s!!!\n", (enuStore == TLS_STORE_FLASH) ? "Flash" : "Firmware Image");
    }

    return ret;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
TLS STORE SAVING
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

static sint8 TlsCertStoreSaveToFlash(uint8 *pu8TlsSrvFlashSecContent, uint8 u8PortNum, uint8 *vflash) {
    sint8 s8Ret = M2M_ERR_FAIL;

    if (programmer_init(&u8PortNum, 0) == M2M_SUCCESS) {
        // dump_flash("Before_tls.bin");

        if (programmer_erase(M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE, NULL) == M2M_SUCCESS) {
            s8Ret = programmer_write(pu8TlsSrvFlashSecContent, M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE, NULL);
        }

        // dump_flash("After_tls.bin");

        programmer_deinit();
    }
    return s8Ret;
}

static sint8 TlsCertStoreSaveToFwImage(uint8 *pu8TlsSrvFlashSecContent, const char *pcFwFile) {
    FILE *fp;
    sint8 s8Ret = M2M_ERR_FAIL;

    fp = fopen(pcFwFile, "rb+");
    if (fp) {
        fseek(fp, M2M_TLS_SERVER_FLASH_OFFSET, SEEK_SET);
        fwrite(pu8TlsSrvFlashSecContent, 1, M2M_TLS_SERVER_FLASH_SIZE, fp);
        fclose(fp);
        s8Ret = M2M_SUCCESS;
    } else {
        printf("(ERR)Cannot Open Fw image <%s>\n", pcFwFile);
    }
    return s8Ret;
}

static sint8 TlsCertStoreSave(const char *pcFwFile, uint8 port, uint8 *vflash) {
    tenuTLSCertStoreType enuStore = strcmp(pcFwFile, "") ? TLS_STORE_FW_IMG : TLS_STORE_FLASH;

    sint8 ret = M2M_ERR_FAIL;
    switch (enuStore) {
        case TLS_STORE_FLASH:
            ret = TlsCertStoreSaveToFlash(gau8TlsSrvSec, port, vflash);
            break;

        case TLS_STORE_FW_IMG:
            ret = TlsCertStoreSaveToFwImage(gau8TlsSrvSec, pcFwFile);
            break;

        default:
            break;
    }

    if (ret == M2M_SUCCESS) {
        printf("TLS Certificate Store Updated Successfully On: %s\n", (enuStore == TLS_STORE_FLASH) ? "Flash" : "Firmware Image");
    } else {
        printf("TLS Certificate Store Update FAILED To %s!!!\n", (enuStore == TLS_STORE_FLASH) ? "Flash" : "Firmware Image");
    }

    return ret;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
READ COMMAND
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

int HandleReadCmd(const char *fwImg, const char *outfile, int verbose, int port) {
    int ret = M2M_ERR_FAIL;

    printf("Dumping TLS Store contents...\n");

    if (port == 0) {
        port = detect_com_port();
    }

    if((ret = TlsCertStoreLoad(fwImg, port, NULL) != M2M_SUCCESS)) {
        return ret;
    }

    printf("- Parsing TLS Store...\n");
    TlsSrvSecReadInit(gau8TlsSrvSec);

    TlsSrvSecDumpContents(1, 1, 1, 1, 1, outfile, verbose);

    printf("\nDumping Root Cert Store contents...\n");
    ret = RootCertStoreLoad(fwImg, port, NULL);
    if (ret != M2M_SUCCESS) {
        return ret;
    }

    DumpRootCerts(outfile);

    return 0;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
UPDATE COMMAND
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

int UpdateTlsStore(const char *fwImg, const char *outfile, const char *key, const char *cert, const char *ca_dir, tenuWriteMode enuMode) {
    int ret = M2M_ERR_FAIL;
    uint32 u32TlsSrvSecSz;

    if (TlsCertStoreLoad(TLS_STORE_FW_IMG, fwImg, 0, NULL) != M2M_SUCCESS) {
        return ret;
    }

    ret = TlsCertStoreWriteCertChain(key, cert, ca_dir, gau8TlsSrvSec, &u32TlsSrvSecSz, enuMode);
    if (ret == M2M_SUCCESS) {
        // Write the TLS Certificate Section buffer to the chosen destination,
        // either to the firmware image or the WINC stacked flash directly.
        ret = TlsCertStoreSave(TLS_STORE_FW_IMG, fwImg, 0, NULL);
    }
    return ret;
}

int UpdateRootCertStore(const char *fwImg, const char *ca_dir, int erase) {
    int ret = M2M_ERR_FAIL;
    uint32 u32Idx;
    uint32 u32nCerts;
    uint32 u32CertSz;
    uint8 *pu8RootCert;
    char **ppCertNames;

    ret = RootCertStoreLoad(ROOT_STORE_FW_IMG, fwImg, 0, NULL);
    if (ret != M2M_SUCCESS) {
        return ret;
    }

    ListDirectoryContents(ca_dir, "cer", &ppCertNames, &u32nCerts);
    if (u32nCerts != 0) {
        for (u32Idx = 0; u32Idx < u32nCerts; u32Idx++) {
            // Reads cert from disk into pu8RootCert
            if (ReadFileToBuffer(ppCertNames[u32Idx], &pu8RootCert, &u32CertSz) == M2M_SUCCESS) {
                if (WriteRootCertificate(pu8RootCert, u32CertSz, NULL) != 0) {
                    printf("Error Writing certificate.\n");
                    free(pu8RootCert);
                    return M2M_ERR_FAIL;
                }
                free(pu8RootCert);
            }
        }

        RootCertStoreSave(ROOT_STORE_FW_IMG, fwImg, 0, NULL);
    } else {
        printf("Unable to find certificates\r\n");
        ret = M2M_ERR_FAIL;
    }
    return ret;
}

int HandleUpdateCmd(const char *fwImg, const char *outfile, const char *key, const char *cert, const char *pf_bin, const char *ca_dir, int erase, int verbose, int port) {
    int ret = M2M_ERR_FAIL;
    tenuWriteMode tlsMode = erase ? TLS_SRV_SEC_MODE_WRITE : TLS_SRV_SEC_MODE_APPEND;

    if (port == 0) {
        port = detect_com_port();
    }

    ret = UpdateTlsStore(fwImg, outfile, key, cert, ca_dir, tlsMode);
    ret = UpdateRootCertStore(fwImg, ca_dir, erase);

    return ret;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
WRITE COMMAND
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

static sint8 LoadFirmware(const char *pcFwFile) {
    FILE *fp;
    sint8 s8Ret = M2M_ERR_FAIL;

    fp = fopen(pcFwFile, "rb");
    if (fp) {
        fread(gauFirmware, 1, sizeof(gauFirmware), fp);
        fclose(fp);
        s8Ret = M2M_SUCCESS;
    } else {
        printf("* Error opening firmware file: <%s>\n", pcFwFile);
    }
    return s8Ret;
}

static sint8 WriteFirmware(uint8 *pu8firmware, uint8 u8PortNum) {
    sint8 s8Ret = M2M_ERR_FAIL;

    if (programmer_init(&u8PortNum, 0) == M2M_SUCCESS) {
        // dump_flash("Before_tls.bin");

        if (programmer_erase(0, sizeof(gauFirmware), NULL) == M2M_SUCCESS) {
            s8Ret = programmer_write(&gauFirmware, 0, sizeof(gauFirmware), NULL);
        }

        // dump_flash("After_tls.bin");

        programmer_deinit();
    }
    return s8Ret;
}

int HandleWriteCmd(const char *fwImg, int port) {
    int ret = M2M_ERR_FAIL;
    printf("Writing firmware to device...\n");

    if (port == 0) {
        port = detect_com_port();
    }

    printf("- Reading firmware from disk...\n");
    if((ret = LoadFirmware(fwImg, port, NULL) != M2M_SUCCESS)) {
        printf("error reading!\n");
        return ret;
    }

    printf("- Writing firmware to device...\n");
    if((ret = WriteFirmware(fwImg, port) != M2M_SUCCESS)) {
        printf("error writing!\n");
        return ret;
    }

    return ret;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
ERASE COMMAND
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

int EraseBuffer(const char *fwImg) {
    FILE *fp;
    sint8 ret = M2M_ERR_FAIL;
    uint8 au8Pattern[] = TLS_SRV_SEC_START_PATTERN;

    // Clear TLS Cert Store buffer
    memset(&gau8TlsSrvSec, 0xFF, M2M_TLS_SERVER_FLASH_SIZE);
    tstrTlsSrvSecHdr *gpstrTlsSrvSecHdr = (tstrTlsSrvSecHdr *)gau8TlsSrvSec;
    memcpy(gpstrTlsSrvSecHdr->au8SecStartPattern, au8Pattern, TLS_SRV_SEC_START_PATTERN_LEN);
    gpstrTlsSrvSecHdr->u32nEntries = 0;
    gpstrTlsSrvSecHdr->u32NextWriteAddr = sizeof(tstrTlsSrvSecHdr) + M2M_TLS_SERVER_FLASH_OFFSET;

    ret = TlsCertStoreSaveToFwImage(&gau8TlsSrvSec, fwImg);

    ret = RootCertStoreLoadFromFwImage(fwImg);
    InitializeMemory();
    ret = RootCertStoreSave(ROOT_STORE_FW_IMG, fwImg, 0, NULL);

    return ret;
}

int HandleEraseCmd(const char *fwImg, int all) {
    EraseBuffer(fwImg);
    return 0;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
MAIN
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#define REG_EXTENDED 1
#define REG_ICASE (REG_EXTENDED << 1)

int main(int argc, char **argv) {
    // Default Arguments
    struct arg_file *infiles = arg_file0(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_file *outfile = arg_file0("o", NULL, "<output directory>", "Directory to dump certs");
    struct arg_int *port = arg_int0("p", "port", "<COM Port>", "COM Port");
    struct arg_lit *verbose  = arg_lit0("v", "verbose", "Output more details");
    struct arg_lit *help = arg_lit0("h", "help", "Show help");
    struct arg_end *end = arg_end(20);

	// Read Command Setup
    struct arg_rex *read_cmd = arg_rex1(NULL, NULL, "read", NULL, REG_ICASE, NULL);
    void *argtable1[] = {read_cmd, infiles, outfile, verbose, port, help, end};
    int nerrors1;

	// Update Command Setup
    struct arg_rex *update_cmd = arg_rex1(NULL, NULL, "update", NULL, REG_ICASE, NULL);
    struct arg_file *key = arg_file0(NULL, "key", "<key>", "Private key in PEM format (RSA Keys only). It MUST NOT be encrypted");
    struct arg_file *cert = arg_file0(NULL, "cert", "<cert>", "X.509 Certificate file in PEM or DER format. The certificate SHALL contain the public key associated with the given private key (If the private key is given)");
    struct arg_file *pf_bin = arg_file0(NULL, "pf_bin", "<pf_bin>", "Programmer binary");
    struct arg_file *ca_dir = arg_file0(NULL, "ca_dir", "<ca_dir>", "[Optional] Path to a folder containing the intermediate CAs and the Root CA of the given certificate");
    struct arg_lit *erase = arg_lit0(NULL, "erase", "Erase the certificate store before writing. If this option is not given, the new certificate material is appended to the certificate store");
    void *argtable2[] = {update_cmd, infiles, outfile, key, cert, pf_bin, ca_dir, erase, verbose, port, help, end};
    int nerrors2;

	// Erase Command Setup
    struct arg_rex *erase_cmd = arg_rex1(NULL, NULL, "erase", NULL, REG_ICASE, NULL);
    struct arg_lit *erase_all = arg_lit0("a", "all", "Erase TLS and Root Cert Stores");
    void *argtable3[] = {erase_cmd, infiles, outfile, erase_all, port, help, end};
    int nerrors3;

	// Write Command Setup
    struct arg_rex *write_cmd = arg_rex1(NULL, NULL, "write", NULL, REG_ICASE, NULL);
    struct arg_file *infiles1 = arg_file1(NULL, NULL, "<firmware image>", "Input firmware binary");
    void *argtable4[] = {write_cmd, infiles1, port, help, end};
    int nerrors4;


    const char *progname = "atwin1500_fwtool.exe";
    int exitcode = 0;

    /* verify all argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable1) != 0 ||
        arg_nullcheck(argtable2) != 0 ||
        arg_nullcheck(argtable3) != 0 ||
        arg_nullcheck(argtable4) != 0) {
        /* NULL entries were detected, some allocations must have failed */
        printf("%s: insufficient memory\n", progname);
        exitcode = 1;
        goto __EXIT;
    }

    // Set default values...
    port->ival[0] = 0;

    if (arg_parse(argc, argv, argtable1) == 0) {
        exitcode = HandleReadCmd(infiles->filename[0], outfile->filename[0], verbose->count, port->ival[0]);
    } else if (arg_parse(argc, argv, argtable2) == 0) {
        exitcode = HandleUpdateCmd(infiles->filename[0], outfile->filename[0], key->filename[0], cert->filename[0], pf_bin->filename[0], ca_dir->filename[0], erase->count, verbose->count, port->ival[0]);
    } else if (arg_parse(argc, argv, argtable3) == 0) {
        exitcode = HandleEraseCmd(infiles->filename[0], erase_all->count);
    } else if (arg_parse(argc, argv, argtable4) == 0) {
        exitcode = HandleWriteCmd(infiles1->filename[0], port->ival[0]);
    } else {
        // We get here if the command line matched none of the possible syntaxes
        if (read_cmd->count > 0) {
            printf("Usage: %s ", progname);
            arg_print_syntax(stdout, argtable1, "\n");

            if (help->count) {
                printf("\nRead X.509 Certificate chain from WINC Device Flash or a given WINC firmware image file\n\n");
                printf("Options:\n");
                arg_print_glossary(stdout, argtable1, "  %-25s %s\n");

                printf("\nExamples: \n");
                printf("  %s read -rsa -privkey -dir\n", progname);
                printf("  %s read -rsa -all\n", progname);
                printf("  %s read -rsa -out C:/Certs/\n", progname);
                printf("  %s read -rsa -ecdsa -dir-fwimg m2m_aio_3a0.bin\n", progname);
                goto __EXIT;
            }
            arg_print_errors(stdout, end, "- error");
        } else if (update_cmd->count > 0) {
            printf("Usage: %s ", progname);
            arg_print_syntax(stdout, argtable2, "\n");

            if (help->count) {
                printf("\nWrite X.509 Certificate chain on WINC Device Flash or a given WINC firmware image file\n\n");
                printf("Options:\n");
                arg_print_glossary(stdout, argtable2, "  %-25s %s\n");

                printf("\nExamples: \n");
                printf("  %s update -key rsa.key -cert rsa.cer -erase\n", progname);
                printf("  %s update -nokey -cert ecdsa.cer -cadir CADir\n", progname);
                printf("  %s update -key rsa.key -cert rsa.cer -cadir CADir\n", progname);
                printf("  %s update -key rsa.key -cert rsa.cer -fwimg m2m_aio_3a0.bin\n", progname);
                goto __EXIT;
            }
            arg_print_errors(stdout, end, "- error");
        } else {
            printf("Usage: %s ", progname);
            arg_print_syntax(stdout, argtable1, "\n");
            printf("       %s ", progname);
            arg_print_syntax(stdout, argtable2, "\n");
            printf("       %s ", progname);
            arg_print_syntax(stdout, argtable3, "\n\n");
            printf("For a specific command help, use <%s <CMD> --help>\n\n", progname);
        }
    }

__EXIT:
    arg_freetable(argtable1, sizeof(argtable1) / sizeof(argtable1[0]));
    arg_freetable(argtable2, sizeof(argtable2) / sizeof(argtable2[0]));
    arg_freetable(argtable3, sizeof(argtable3) / sizeof(argtable3[0]));

    return exitcode;
}
