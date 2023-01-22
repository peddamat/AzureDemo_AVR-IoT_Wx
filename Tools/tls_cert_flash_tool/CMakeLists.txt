cmake_minimum_required (VERSION 3.8)
add_compile_options(-DCONF_WINC_USE_UART -g2)
set(CMAKE_BUILD_TYPE Debug)

project(TlsCertTool)

add_executable(TlsCertTool main.c
../../common/argtable/argtable3.c
../../common/simple_uart/simple_uart.c
../../common/root_cert/pem.c
../../common/root_cert/root_setup.c
../../common/root_cert/tls_cert_store_win.c
../../common/root_cert/tls_srv_sec.c
../../host_drv/bsp/source/nm_bsp_linux.c
../../host_drv/bus_wrapper/source/nm_bus_wrapper_linux_uart.c
../../host_drv/common/source/nm_common.c
../../host_drv/driver/source/nmasic.c
../../host_drv/driver/source/nmbus.c
../../host_drv/driver/source/nmdrv.c
../../host_drv/driver/source/nmi2c.c
../../host_drv/driver/source/nmspi.c
../../host_drv/driver/source/nmuart.c
../../host_drv/spi_flash/source/spi_flash.c
../programmer/programmer.c)

add_library( CryptoLib SHARED IMPORTED GLOBAL )
# You can define two import-locations: one for debug and one for release.
set_target_properties( CryptoLib PROPERTIES IMPORTED_LOCATION ../../crypto_lib/build/libCryptoLib.dylib )

# add_library(CryptoLib SHARED IMPORTED) # or STATIC instead of SHARED
# link_directories(../../crypto_lib)
target_link_libraries(TlsCertTool CryptoLib)


# add_library(CryptoLib SHARED crypto_lib_api.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/crypto/aes.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/crypto/aes_cbc.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/crypto/aes_gcm.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/crypto/bigint.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/crypto/hash.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/crypto/rsa.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/tls/x509/asn1.c
# ../../firmware/wifi_v111/src/nmi_m2m/source/tls/x509/x509_cert.c
# ../source/rsa_key.c
# ../../common/root_cert/pem.c
# ../source/tls_buffer_manager.c
# ../source/crypto_port.c)

# include_directories("include")
# include_directories("../crypto_lib/include")
# include_directories("../../firmware/wifi_v111/src/nmi_m2m/include")
# include_directories("source")
# include_directories("../../host_drv")
# include_directories("../../common/host_fw")
# include_directories("../../common/root_cert")
# include_directories("../../firmware/wifi_v111/src/nmi_m2m/source/tls/x509/")

include_directories("../crypto_lib/include")
include_directories("../../common/simple_uart")
include_directories("../../common/spi_flash_mapping")
include_directories("../../common/root_cert")
include_directories("../../host_drv")
include_directories("../../host_drv/source/spi_flash")
include_directories("../programmer")
