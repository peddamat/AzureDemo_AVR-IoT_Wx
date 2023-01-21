cmake_minimum_required (VERSION 3.8)

project(CryptoLib)

add_library(CryptoLib SHARED crypto_lib_api.c
../../firmware/wifi_v111/src/nmi_m2m/source/crypto/aes.c
../../firmware/wifi_v111/src/nmi_m2m/source/crypto/aes_cbc.c
../../firmware/wifi_v111/src/nmi_m2m/source/crypto/aes_gcm.c
../../firmware/wifi_v111/src/nmi_m2m/source/crypto/bigint.c
../../firmware/wifi_v111/src/nmi_m2m/source/crypto/hash.c
../../firmware/wifi_v111/src/nmi_m2m/source/crypto/rsa.c
../../firmware/wifi_v111/src/nmi_m2m/source/tls/x509/asn1.c
../../firmware/wifi_v111/src/nmi_m2m/source/tls/x509/x509_cert.c
../source/rsa_key.c
../../common/root_cert/pem.c
../source/tls_buffer_manager.c
../source/crypto_port.c)

include_directories("include")
include_directories("../../firmware/wifi_v111/src/nmi_m2m/include")
include_directories("source")
include_directories("../../host_drv")
include_directories("../../common/host_fw")
include_directories("../../common/root_cert")
include_directories("../../firmware/wifi_v111/src/nmi_m2m/source/tls/x509/")
