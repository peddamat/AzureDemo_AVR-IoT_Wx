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
#include <string.h>
#include <stdlib.h>
#include "driver\include\m2m_types.h"
#include "crypto_lib_api.h"
#include "programmer.h"
#include "tls_srv_sec.h"
#include "../common/argtable/argtable3.h"

#include "root_setup.h"


extern sint8 TlsCertStoreWriteCertChain(const char *pcPrivKeyFile, const char *pcSrvCertFile, const char *pcCADirPath, uint8 *pu8TlsSrvSecBuff, uint32 *pu32SecSz, tenuWriteMode enuMode);

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
MACROS
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

#define STIRCMP(argvPtr, text)	\
	(!_strnicmp((argvPtr), (text), strlen((text))))

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
DATA TYPES
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/


typedef enum{
	TLS_STORE_INVALID,
	TLS_STORE_FLASH,
	TLS_STORE_FW_IMG
}tenuTLSCertStoreType;


typedef enum{
	CMD_WRITE,
	CMD_READ
}tenuCmd;

/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
GLOBALS
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/

static uint8 gau8RootCertMem[M2M_TLS_ROOTCER_FLASH_SIZE];
static uint8 gau8TlsSrvSec[M2M_TLS_SERVER_FLASH_SIZE];

void dump_flash(char * filename)
{
//#define DUMP_FLASH
#ifdef DUMP_FLASH
	M2M_PRINT("Dumping flash to %s\n", filename);
	FILE *fp;
	uint8 * pf;
	uint32 sz = programmer_get_flash_size();
	pf = malloc(sz);
	if(pf != NULL)
	{
		programmer_read(pf,0,sz);
		fp = fopen(filename,"wb");
		if(fp != NULL)
		{
			fwrite(pf,1,sz,fp);
			fclose(fp);
		}
		free(pf);
	}

#endif
}

static sint8 TlsCertStoreSaveToFlash(uint8 *pu8TlsSrvFlashSecContent, uint8 u8PortNum, uint8* vflash)
{
	sint8	s8Ret = M2M_ERR_FAIL;

	if(programmer_init(&u8PortNum, 0) == M2M_SUCCESS)
	{
        dump_flash("Before_tls.bin");

		if(programmer_erase(M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE, vflash) == M2M_SUCCESS)
		{
			s8Ret = programmer_write(pu8TlsSrvFlashSecContent, M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE, vflash);
		}

        dump_flash("After_tls.bin");

		programmer_deinit();
	}
	return s8Ret;
}

static sint8 TlsCertStoreLoadFromFlash(uint8 u8PortNum)
{
	sint8	s8Ret = M2M_ERR_FAIL;

	if(programmer_init(&u8PortNum, 0) == M2M_SUCCESS)
	{
		s8Ret = programmer_read(gau8TlsSrvSec, M2M_TLS_SERVER_FLASH_OFFSET, M2M_TLS_SERVER_FLASH_SIZE);
		programmer_deinit();
	}
	return s8Ret;
}

static sint8 TlsCertStoreSaveToFwImage(uint8 *pu8TlsSrvFlashSecContent, const char *pcFwFile)
{
	FILE	*fp;
	sint8	s8Ret	= M2M_ERR_FAIL;

	fp = fopen(pcFwFile, "rb+");
	if(fp)
	{
		fseek(fp, M2M_TLS_SERVER_FLASH_OFFSET, SEEK_SET);
		fwrite(pu8TlsSrvFlashSecContent, 1, M2M_TLS_SERVER_FLASH_SIZE, fp);
		fclose(fp);
		s8Ret = M2M_SUCCESS;
	}
	else
	{
		printf("(ERR)Cannot Open Fw image <%s>\n", pcFwFile);
	}
	return s8Ret;
}

static sint8 TlsCertStoreLoadFromFwImage(const char *pcFwFile)
{
	FILE	*fp;
	sint8	s8Ret	= M2M_ERR_FAIL;

	fp = fopen(pcFwFile, "rb");
	if(fp)
	{
		fseek(fp, M2M_TLS_SERVER_FLASH_OFFSET, SEEK_SET);
		fread(gau8TlsSrvSec, 1, M2M_TLS_SERVER_FLASH_SIZE, fp);
		fclose(fp);
		s8Ret = M2M_SUCCESS;
	}
	else
	{
		printf("(ERR)Cannot Open Fw image <%s>\n", pcFwFile);
	}
	return s8Ret;
}

static sint8 TlsCertStoreSave(tenuTLSCertStoreType enuStore, const char *pcFwFile, uint8 port, uint8* vflash)
{
	sint8	ret = M2M_ERR_FAIL;

	switch(enuStore)
	{
	case TLS_STORE_FLASH:
		ret = TlsCertStoreSaveToFlash(gau8TlsSrvSec, port, vflash);
		break;

	case TLS_STORE_FW_IMG:
		ret = TlsCertStoreSaveToFwImage(gau8TlsSrvSec, pcFwFile);
		break;

	default:
		break;
	}

	if(ret == M2M_SUCCESS)
	{
		printf("TLS Certificate Store Update Success on %s\n", (enuStore == TLS_STORE_FLASH) ? "Flash" : "Firmware Image");
	}
	else
	{
		printf("TLS Certificate Store Update FAILED !!! on %s\n", (enuStore == TLS_STORE_FLASH) ? "Flash" : "Firmware Image");
	}
	return ret;
}

sint8 TlsCertStoreLoad(tenuTLSCertStoreType enuStore, const char *pcFwFile, uint8 port, uint8* vflash)
{
	sint8	ret = M2M_ERR_FAIL;

	switch(enuStore)
	{
	case TLS_STORE_FLASH:
		ret = TlsCertStoreLoadFromFlash(port);
		break;

	case TLS_STORE_FW_IMG:
		ret = TlsCertStoreLoadFromFwImage(pcFwFile);
		break;

	default:
		break;
	}
	return ret;
}

int ReadCertFromDisk(char *pcFileName, uint8 **ppu8FileData, uint32 *pu32FileSize)
{
	FILE	*fp;
	int		ret = M2M_ERR_FAIL;

	fp = fopen(pcFileName, "rb");
	if(fp)
	{
		uint32	u32FileSize;
		uint8	*pu8Buf;

		fseek(fp, 0, SEEK_END);
		u32FileSize = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		pu8Buf = (uint8*)malloc(u32FileSize);
		if(pu8Buf != NULL)
		{
			fread(pu8Buf, 1, u32FileSize, fp);
			*pu32FileSize = u32FileSize;
			*ppu8FileData = pu8Buf;
			ret = M2M_SUCCESS;
		}
		fclose(fp);
	}
	return ret;
}

int HandleReadCmd(const char *fwImg, const char *outfile)
{
	int ret = M2M_ERR_FAIL;

	// Dump TLS Store contents
	ret = TlsCertStoreLoad(TLS_STORE_FW_IMG, fwImg, 0, NULL);
	if (ret != M2M_SUCCESS)
	{
		return ret;
	}

	TlsSrvSecReadInit(gau8TlsSrvSec);
	TlsSrvSecDumpContents(1,1,1,1,1, 1, outfile);

	// Dump Root Cert Store Contents
	ret = RootCertStoreLoad(ROOT_STORE_FW_IMG, fwImg, 0, NULL);
	if (ret != M2M_SUCCESS)
	{
		return ret;
	}

	DumpRootCerts();

    return 0;
}

int HandleUpdateCmd(const char *fwImg, const char *outfile, const char *key, const char *cert, const char *pf_bin, const char *ca_dir, int erase)
{
    int ret = M2M_ERR_FAIL;
	uint32	u32TlsSrvSecSz;

    tenuWriteMode enuMode;

    if (cert == NULL) {
		printf("Server Certificate File MUST Be Supplied\n");
		return ret;
	}

	if(erase == 1)
	{
		/* Clean write after erasing the current TLS Certificate section contents.  */
		enuMode = TLS_SRV_SEC_MODE_WRITE;
	}
	else
	{
		/* Write to the end of the current TLS Certificate section.  */
		enuMode = TLS_SRV_SEC_MODE_APPEND;
		if(TlsCertStoreLoad(enuMode, outfile, 0, NULL) != M2M_SUCCESS)
		{
			return ret;
		}
	}

	/* Modify the TLS Certificate Store Contents.  */
	ret = TlsCertStoreWriteCertChain(key, cert, ca_dir, gau8TlsSrvSec, &u32TlsSrvSecSz, enuMode);
	if(ret == M2M_SUCCESS)
	{
		/* Write the TLS Certificate Section buffer to the chosen destination,
			either to the firmware image or the WINC stacked flash directly.  */
		ret = TlsCertStoreSave(enuMode, fwImg, 0, NULL);
	}


	ret = RootCertStoreLoad(ROOT_STORE_FW_IMG, fwImg, 0, NULL);
	if (ret != M2M_SUCCESS)
	{
		return ret;
	}

#if 0
	for(int i = 0; i < 1; i++)
	{
		uint32	u32RootCertSz;
		uint8	*pu8RootCertBuff;

		if(ReadCertFromDisk(in->filename[i], &pu8RootCertBuff, &u32RootCertSz) == M2M_SUCCESS)
		{
			if(WriteRootCertificate(pu8RootCertBuff, u32RootCertSz, NULL) != 0)
			{
				printf("Error writing certificate.\n");
				ret = -1;
				break;
			}
		}
	}
#endif
}

#define REG_EXTENDED 1
#define REG_ICASE (REG_EXTENDED << 1)

int main(int argc, char **argv)
{
    struct arg_rex  *read_cmd     = arg_rex1(NULL,  NULL,  "read", NULL, REG_ICASE, NULL);
    struct arg_file *infiles1 = arg_file1(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_file *outfile1 = arg_file0("o",  NULL,  "<output directory>", "Directory to dump certs");
    struct arg_lit *help1 = arg_lit0("h",  "help",  "Show help");
    struct arg_end  *end1     = arg_end(20);
    void* argtable1[] = {read_cmd,infiles1,outfile1,help1,end1};
    int nerrors1;

    struct arg_rex  *update_cmd     = arg_rex1(NULL, NULL, "update", NULL, REG_ICASE, NULL);
    struct arg_file *infiles2 = arg_file1(NULL, NULL, "<firmware image>", "Input firmware binary");
    struct arg_file *outfile2 = arg_file0("o",  NULL,  "<output>", "output file (default is \"-\")");
    struct arg_file *key = arg_file0(NULL, "key", "<key>", "Private key in PEM format (RSA Keys only). It MUST NOT be encrypted");
    struct arg_file *cert = arg_file1(NULL, "cert", "<cert>", "X.509 Certificate file in PEM or DER format. The certificate SHALL contain the public key associated with the given private key (If the private key is given)");
    struct arg_file *pf_bin = arg_file0(NULL, "pf_bin", "<pf_bin>", "Programmer binary");
    struct arg_file *ca_dir = arg_file1(NULL, "ca_dir", "<ca_dir>", "[Optional] Path to a folder containing the intermediate CAs and the Root CA of the given certificate.CA cert directory");
    struct arg_lit *erase = arg_lit0(NULL, "erase", "Erase the certificate store before writing. If this option is not given, the new certificate material is appended to the certificate store");
    struct arg_lit *help2 = arg_lit0("h",  "help",  "Show help");
    struct arg_end  *end2     = arg_end(20);
    void* argtable2[] = {update_cmd,infiles2, outfile2, key, cert, pf_bin, ca_dir, erase, help2, end2};
    int nerrors2;

    const char* progname = "atwin1500_fwtool.exe";
    int exitcode=0;

    /* verify all argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable1)!=0 ||
        arg_nullcheck(argtable2)!=0 )
	{
        /* NULL entries were detected, some allocations must have failed */
        printf("%s: insufficient memory\n",progname);
        exitcode=1;
        goto __EXIT;
	}

    nerrors1 = arg_parse(argc,argv,argtable1);
    nerrors2 = arg_parse(argc,argv,argtable2);

    if (nerrors1==0)
	{
        exitcode = HandleReadCmd(infiles1->filename[0], outfile1->filename[0]);
	}
    else if (nerrors2==0)
	{
        exitcode = HandleUpdateCmd(infiles2->filename[0], outfile2->filename[0], key->filename[0], cert->filename[0], pf_bin->filename[0], ca_dir->filename[0], erase->count);
	}
	else
	{
		// We get here if the command line matched none of the possible syntaxes
		if (read_cmd->count > 0)
		{
			printf("Usage: %s ", progname);  arg_print_syntax(stdout,argtable1,"\n");

			if(help1->count)
			{
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
			arg_print_errors(stdout,end1,"- error");
		}
		else if (update_cmd->count > 0)
		{
			printf("Usage: %s ", progname);  arg_print_syntax(stdout,argtable2,"\n");

			if(help2->count)
			{
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
			arg_print_errors(stdout,end2,"- error");
		}
		else
		{
			printf("Usage: %s ", progname);  arg_print_syntax(stdout,argtable1,"\n");
			printf("       %s ", progname);  arg_print_syntax(stdout,argtable2,"\n\n");
			printf("For a specific command help, use <%s <CMD> --help>\n\n", progname);
		}
	}

__EXIT:
	arg_freetable(argtable1,sizeof(argtable1)/sizeof(argtable1[0]));
	arg_freetable(argtable2,sizeof(argtable2)/sizeof(argtable2[0]));

	return exitcode;
}
