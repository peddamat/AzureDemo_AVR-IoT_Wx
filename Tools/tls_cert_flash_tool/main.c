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

        if (programmer_erase(M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE, NULL) == M2M_SUCCESS) {
            s8Ret = programmer_write(pu8TlsSrvFlashSecContent, M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE, NULL);
        }

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

    port = GetPortIfNeeded(fwImg, port, FALSE);

    if((ret = TlsCertStoreLoad(fwImg, port, NULL) != M2M_SUCCESS)) {
        return ret;
    }

    //printf("- Parsing TLS Store...\n");
    TlsSrvSecReadInit(gau8TlsSrvSec);

    TlsSrvSecDumpContents(1, 1, 1, 1, 1, outfile, verbose);

    printf("Dumping Root Cert Store contents...\n");
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

int UpdateTlsStore(const char *fwImg, const char *outfile, const char *key, const char *cert, const char *ca_dir, tenuWriteMode enuMode, int port) {
    int ret = M2M_ERR_FAIL;
    uint32 u32TlsSrvSecSz;

    if((ret = TlsCertStoreLoad(fwImg, port, NULL) != M2M_SUCCESS)) {
        return ret;
    }

    ret = TlsCertStoreWriteCertChain(key, cert, ca_dir, gau8TlsSrvSec, &u32TlsSrvSecSz, enuMode);
    if (ret == M2M_SUCCESS) {
        // Write the TLS Certificate Section buffer to the chosen destination,
        // either to the firmware image or the WINC stacked flash directly.
        ret = TlsCertStoreSave(fwImg, port, NULL);
    }
    return ret;
}

int UpdateRootCertStore(const char *fwImg, const char *ca_dir, int erase, int port) {
    int ret = M2M_ERR_FAIL;
    uint32 u32Idx;
    uint32 u32nCerts;
    uint32 u32CertSz;
    uint8 *pu8RootCert;
    char **ppCertNames;

    if((ret = RootCertStoreLoad(fwImg, port, NULL) != M2M_SUCCESS)) {
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

        ret = RootCertStoreSave(fwImg, port, NULL);
    } else {
        printf("Unable to find certificates\r\n");
        ret = M2M_ERR_FAIL;
    }
    return ret;
}

int GetPortIfNeeded(const char *fwImg, int port, boolean force) {

    // If we're not operating on a local firmware image...
    if (force || (strcmp(fwImg, "") == 0)) {
        // ... and no port is specified
        if (port == 0) {
            // let's assume t
            return detect_com_port();
        }
        else {
            return port;
        }
    }
}

int HandleUpdateRootCmd(const char *fwImg, const char *outfile, const char *ca_dir, int erase, int port) {
    int ret = M2M_ERR_FAIL;
    tenuWriteMode tlsMode = erase ? TLS_SRV_SEC_MODE_WRITE : TLS_SRV_SEC_MODE_APPEND;

    port = GetPortIfNeeded(fwImg, port, FALSE);

    ret = UpdateRootCertStore(fwImg, ca_dir, erase, port);

    return ret;
}

int HandleUpdateTlsCmd(const char *fwImg, const char *outfile, const char *key, const char *cert, const char *ca_dir, int erase, int port) {
    int ret = M2M_ERR_FAIL;
    tenuWriteMode tlsMode = erase ? TLS_SRV_SEC_MODE_WRITE : TLS_SRV_SEC_MODE_APPEND;

    port = GetPortIfNeeded(fwImg, port, FALSE);

    ret = UpdateTlsStore(fwImg, outfile, key, cert, ca_dir, tlsMode, port);

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

    // Force the port check since writes are always over USB/serial
    port = GetPortIfNeeded(fwImg, port, TRUE);

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

int HandleEraseCmd(const char *fwImg, int tls, int root, int port) {
    sint8 ret = M2M_ERR_FAIL;
    uint8 au8Pattern[] = TLS_SRV_SEC_START_PATTERN;

    printf("Erasing device...\n");

    port = GetPortIfNeeded(fwImg, port, FALSE);

    if (tls) {
        InitializeTlsStore(&gau8TlsSrvSec, au8Pattern);
		ret = TlsCertStoreSave(fwImg, port, NULL);
    }

    if (root) {
        InitializeRootCertStore();
        ret = RootCertStoreSave(fwImg, port, NULL);
    }

    return ret;
}

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
MAIN
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#define REG_EXTENDED 1
#define REG_ICASE (REG_EXTENDED << 1)

int main(int argc, char **argv) {

	// Read Command Setup
    struct arg_rex *read_cmd = arg_rex1(NULL, NULL, "read", NULL, REG_ICASE, NULL);
    struct arg_file *infiles1 = arg_file0(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_file *outfile1 = arg_file0("o", NULL, "<output directory>", "Directory to dump certs");
    struct arg_int *port1 = arg_int0("p", "port", "<COM Port>", "COM Port");
    struct arg_lit *verbose1  = arg_lit0("v", "verbose", "Output more details");
    struct arg_lit *help1 = arg_lit0("h", "help", "Show help");
    struct arg_end *end1 = arg_end(20);

    void *argtable1[] = {read_cmd, infiles1, outfile1, verbose1, port1, help1, end1};
    int nerrors1;

	// Update Command Setup
    struct arg_rex *update_cmd2 = arg_rex1(NULL, NULL, "update", NULL, REG_ICASE, NULL);
    struct arg_file *infiles2 = arg_file0(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_file *outfile2 = arg_file0("o", NULL, "<output directory>", "Directory to dump certs");
    struct arg_file *key2 = arg_file0(NULL, "key", "<key>", "Private key in PEM format (RSA Keys only). It MUST NOT be encrypted");
    struct arg_file *cert2 = arg_file0(NULL, "cert", "<cert>", "X.509 Certificate file in PEM or DER format");
    struct arg_lit *update_tls = arg_lit0("t", "tls", "TLS Store");
    struct arg_lit *update_root = arg_lit0("r", "root", "Update Root Store");
    struct arg_file *ca_dir2 = arg_file0(NULL, "ca_dir", "<ca_dir>", "Path to folder containing intermediate CAs and/or Root CA of given certificate");
    struct arg_lit *erase2 = arg_lit0(NULL, "erase", "Erase the cert store before writing. If this option is not given, the new certificate material is appended to the certificate store");
    struct arg_int *port2 = arg_int0("p", "port", "<COM Port>", "COM Port");
    struct arg_lit *help2 = arg_lit0("h", "help", "Show help");
    struct arg_end *end2 = arg_end(20);

    void *argtable2[] = {update_cmd2, infiles2, outfile2, key2, cert2, update_tls, update_root, ca_dir2, erase2, port2, help2, end2};
    int nerrors2;

	// Erase Command Setup
    struct arg_rex *erase_cmd = arg_rex1(NULL, NULL, "erase", NULL, REG_ICASE, NULL);
    struct arg_file *infiles3 = arg_file0(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_lit *erase_tls = arg_lit0("t", "tls", "Erase TLS Store");
    struct arg_lit *erase_root = arg_lit0("r", "root", "Erase Root Store");
    struct arg_int *port3 = arg_int0("p", "port", "<COM Port>", "COM Port");
    struct arg_lit *help3 = arg_lit0("h", "help", "Show help");
    struct arg_end *end3 = arg_end(20);

    void *argtable3[] = {erase_cmd, infiles3, erase_tls, erase_root, port3, help3, end3};
    int nerrors3;

	// Write Command Setup
    struct arg_rex *write_cmd = arg_rex1(NULL, NULL, "write", NULL, REG_ICASE, NULL);
    struct arg_file *infiles5 = arg_file1(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_int *port5 = arg_int0("p", "port", "<COM Port>", "COM Port");
    struct arg_lit *help5 = arg_lit0("h", "help", "Show help");
    struct arg_end *end5 = arg_end(20);

    void *argtable5[] = {write_cmd, infiles5, port5, help5, end5};
    int nerrors5;


    const char *progname = "atwin1500_fwtool.exe";
    int exitcode = 0;

    /* verify all argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable1) != 0 ||
        arg_nullcheck(argtable2) != 0 ||
        arg_nullcheck(argtable3) != 0 ||
        arg_nullcheck(argtable5) != 0) {
        /* NULL entries were detected, some allocations must have failed */
        printf("%s: insufficient memory\n", progname);
        exitcode = 1;
        goto __EXIT;
    }

    // Set default values...
    port1->ival[0] = 0;
    port2->ival[0] = 0;
    port3->ival[0] = 0;
    port5->ival[0] = 0;

    if (arg_parse(argc, argv, argtable1) == 0) {
        if (help1->count == 1) goto __READ;
        exitcode = HandleReadCmd(infiles1->filename[0], outfile1->filename[0], verbose1->count, port1->ival[0]);
    } else if (arg_parse(argc, argv, argtable2) == 0) {
        if (help2->count == 1) goto __UPDATE;
        if (update_tls->count == 1) {
			if (!(infiles2->count | outfile2->count | key2->count | cert2->count | ca_dir2->count | erase2->count)) goto __UPDATE;
            exitcode = HandleUpdateTlsCmd(infiles2->filename[0], outfile2->filename[0], key2->filename[0], cert2->filename[0], ca_dir2->filename[0], erase2->count, port2->ival[0]);
        }
        else if (update_root->count == 1) {
			if (!(infiles2->count | outfile2->count | ca_dir2->count | erase2->count)) goto __UPDATE;
            exitcode = HandleUpdateRootCmd(infiles2->filename[0], outfile2->filename[0], ca_dir2->filename[0], erase2->count, port2->ival[0]);
        }
        else {
            goto __UPDATE;
        }
    } else if (arg_parse(argc, argv, argtable3) == 0) {
        if (help3->count == 1) goto __ERASE;
        if (!(erase_tls->count | erase_root->count)) goto __ERASE;
        exitcode = HandleEraseCmd(infiles3->filename[0], erase_tls->count, erase_root->count, port3->ival[0]);
    } else if (arg_parse(argc, argv, argtable5) == 0) {
        if (help5->count == 1) goto __WRITE;
        exitcode = HandleWriteCmd(infiles5->filename[0], port5->ival[0]);
    } else {
        // We get here if the command line matched none of the possible syntaxes
        if (read_cmd->count > 0) {
__READ:
            printf("\nUsage: %s ", progname);
            arg_print_syntax(stdout, argtable1, "\n");

            if (help1->count) {
                printf("\nRead contents of Root Cert Store and TLS Server Store from WINC Device or a given WINC firmware image\n\n");
                printf("Options:\n");
                arg_print_glossary(stdout, argtable1, "  %-25s %s\n");

                printf("\nExamples: \n");
                printf("  %s read -o <output dir>\n", progname);
                printf("  %s read atwinc1500.bin\n", progname);
                printf("  %s read atwinc1500.bin -v\n", progname);
                goto __EXIT;
            }
            arg_print_errors(stdout, end1, "- error");
        } else if (update_cmd2->count > 0) {
__UPDATE:
            printf("\nUsage: %s ", progname);
            arg_print_syntax(stdout, argtable2, "\n");

            if (help2->count) {
                printf("\nUpdate contents of Root Cert Store or TLS Server Store from WINC Device or a given WINC firmware image\n\n");
                printf("Options:\n");
                arg_print_glossary(stdout, argtable2, "  %-25s %s\n");

                printf("\nExamples: \n");
                printf("  %s update atwinc1500.bin --tls -key rsa.key\n", progname);
                printf("  %s update --tls -key rsa.key --cert rsa.cer --erase\n", progname);
                printf("  %s update --root --cadir <dir>\n", progname);
                goto __EXIT;
            }
            arg_print_errors(stdout, end2, "- error");
        } else if (erase_cmd->count > 0) {
__ERASE:
            printf("\nUsage: %s ", progname);
            arg_print_syntax(stdout, argtable3, "\n");

            if (help3->count) {
                printf("\nErase contents of Root Cert Store or TLS Server Store from WINC Device or a given WINC firmware image\n\n");
                printf("Options:\n");
                arg_print_glossary(stdout, argtable3, "  %-25s %s\n");

                printf("\nExamples: \n");
                printf("  %s erase --root\n", progname);
                printf("  %s erase --tls\n", progname);
                printf("  %s erase atwinc1500.bin --root --tls\n", progname);
                goto __EXIT;
            }
            arg_print_errors(stdout, end3, "- error");
        } else if (write_cmd->count > 0) {
__WRITE:
            printf("\nUsage: %s ", progname);
            arg_print_syntax(stdout, argtable5, "\n");

            if (help5->count) {
                printf("\nWrite WINC firmware image file to device\n\n");
                printf("Options:\n");
                arg_print_glossary(stdout, argtable5, "  %-25s %s\n");

                printf("\nExamples: \n");
                printf("  %s write -key rsa.key -cert rsa.cer -erase\n", progname);
                printf("  %s write -key rsa.key -cert rsa.cer -fwimg m2m_aio_3a0.bin\n", progname);
                goto __EXIT;
            }
            arg_print_errors(stdout, end5, "- error");

        } else {
            printf("\nUsage: %s ", progname);
            arg_print_syntax(stdout, argtable1, "\n");
            printf("       %s ", progname);
            arg_print_syntax(stdout, argtable2, "\n");
            printf("       %s ", progname);
            arg_print_syntax(stdout, argtable3, "\n");
            printf("       %s ", progname);
            arg_print_syntax(stdout, argtable5, "\n\n");

            printf("For a specific command help, use <%s <CMD> --help>\n\n", progname);
        }
    }

__EXIT:
    arg_freetable(argtable1, sizeof(argtable1) / sizeof(argtable1[0]));
    arg_freetable(argtable2, sizeof(argtable2) / sizeof(argtable2[0]));
    arg_freetable(argtable3, sizeof(argtable3) / sizeof(argtable3[0]));
    arg_freetable(argtable5, sizeof(argtable5) / sizeof(argtable5[0]));

    return exitcode;
}
