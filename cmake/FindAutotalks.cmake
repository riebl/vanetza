if(NOT AUTOTALKS_CRATON)
    find_path(
        AUTOTALKS_ROOT
        NAMES "include/atlk/v2x_service.h"
        PATH_SUFFIXES "autotalks_secton_api"
        PATHS $ENV{HOME}
        CMAKE_FIND_ROOT_PATH_BOTH # Seems like this is not needed in newer CMake
    )

    set(AUTOTALKS_INCLUDE_DIRS "${AUTOTALKS_ROOT}/include" "${AUTOTALKS_ROOT}/ref_src/include" "${AUTOTALKS_ROOT}/depend/device/include" "${AUTOTALKS_ROOT}/src/include" "${AUTOTALKS_ROOT}/src/core/include")
    set(AUTOTALKS_LIBS_DIR ${AUTOTALKS_ROOT}/output.sec/x86/lib)
    set(AUTOTALKS_OBJ_DIR ${AUTOTALKS_ROOT}/output.sec/x86/obj)

    # Secton does not need ToMcrypt and ToMmath as Craton

    set(AUTOTALKS_OBJECTS target_type/target_type_remote.o platform_type/platform_type_linux_u.o link_layer/linux_u/remote/link_layer_remote.o link_layer/linux_u/ipc/link_layer_ipc.o link_layer/linux_u/tee/link_layer_tee_stub.o link_layer/link_layer_interface.o flash_reader/linux_u/remote/flash_reader_remote.o ref_sys/ref_sys.o ref_sys/ref_sys_logger.o log_reader/log_reader.o secure_hdif_crypto_layer/crypto_layer_ref_sys.o secure_hdif_crypto_layer/crypto_layer_interface.o secure_hdif_crypto_layer/crypto_lib_wrapper.o secure_storage/secure_storage.o time_sync/time_sync.o time_sync/time_sync_poti.o poti_lib/gnss/gnss.o poti_lib/nmea/nmea.o poti_lib/nmea/nmea_io.o poti_lib/nmea/nmea_io_check.o poti_lib/nmea/nmea_nav.o poti_lib/nmea/nmea_parse.o poti_lib/gnss/teseo/teseo.o poti_lib/gnss/teseo/teseo_commands.o poti_lib/coord/coord.o poti_lib/periodic_alarm/periodic_alarm.o poti_lib/api/poti_api.o poti_lib/ubx/serial_driver.o poti_lib/ubx/ubx_driver.o poti_lib/ubx/ubx_nav.o)
    list(TRANSFORM AUTOTALKS_OBJECTS PREPEND ${AUTOTALKS_OBJ_DIR}/)

    if (NOT TARGET Autotalks::AtlkRemote)
        add_library(Autotalks::AtlkRemote UNKNOWN IMPORTED)
        set_target_properties(Autotalks::AtlkRemote PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_LIBS_DIR}/libatlkremote_linux_u.so"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
        set_property(TARGET Autotalks::AtlkRemote APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES ${AUTOTALKS_OBJECTS} rt)
        # target_link_libraries not working properly in CMake v3.5.1 used in Ubuntu 16.04
    endif()

else() # Craton device
    find_path(
        AUTOTALKS_ROOT
        NAMES "include/atlk/v2x_service.h"
        PATHS $ENV{HOME}
        PATH_SUFFIXES "autotalks_craton_api"
        CMAKE_FIND_ROOT_PATH_BOTH # Seems like this is not needed in newer CMake
    )

    set(AUTOTALKS_INCLUDE_DIRS "${AUTOTALKS_ROOT}/include" "${AUTOTALKS_ROOT}/ref_src/include" "${AUTOTALKS_ROOT}/depend/device/include" "${AUTOTALKS_ROOT}/src/include" "${AUTOTALKS_ROOT}/src/core/include")

    set(AUTOTALKS_LIBS_DIR ${AUTOTALKS_ROOT}/output.cr2_lnx/armv7-32/lib)
    set(AUTOTALKS_OBJ_DIR ${AUTOTALKS_ROOT}/output.cr2_lnx/armv7-32/obj)

    if (NOT TARGET Autotalks::ToMcrypt)
        add_library(Autotalks::ToMcrypt UNKNOWN IMPORTED)
        set_target_properties(Autotalks::ToMcrypt PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_LIBS_DIR}/libtomcrypt.a"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
    endif()

    if (NOT TARGET Autotalks::ToMmath)
        add_library(Autotalks::ToMmath UNKNOWN IMPORTED)
        set_target_properties(Autotalks::ToMmath PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_LIBS_DIR}/libtommath.a"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
    endif()

    if (NOT TARGET Autotalks::Optee)
        add_library(Autotalks::Optee UNKNOWN IMPORTED)
        set_target_properties(Autotalks::Optee PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_ROOT}/depend/optee/lib/libteec.so"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
    endif()

    set(AUTOTALKS_OBJECTS target_type/target_type_local.o platform_type/platform_type_linux_u.o link_layer/linux_u/local/link_layer_local_shared_memory.o link_layer/linux_u/ipc/link_layer_ipc.o link_layer/linux_u/tee/static_list.o link_layer/linux_u/tee/link_layer_tee.o link_layer/link_layer_interface.o flash_reader/linux_u/local/flash_reader_local.o ref_sys/ref_sys.o ref_sys/ref_sys_logger.o log_reader/log_reader.o secure_hdif_crypto_layer/crypto_layer_stubs.o time_sync/time_sync.o time_sync/time_sync_poti.o poti_lib/gnss/gnss.o poti_lib/nmea/nmea.o poti_lib/nmea/nmea_io.o poti_lib/nmea/nmea_io_check.o poti_lib/nmea/nmea_nav.o poti_lib/nmea/nmea_parse.o poti_lib/gnss/teseo/teseo.o poti_lib/gnss/teseo/teseo_commands.o poti_lib/coord/coord.o poti_lib/periodic_alarm/periodic_alarm.o poti_lib/api/poti_api.o poti_lib/ubx/serial_driver.o poti_lib/ubx/ubx_driver.o poti_lib/ubx/ubx_nav.o)
    list(TRANSFORM AUTOTALKS_OBJECTS PREPEND ${AUTOTALKS_OBJ_DIR}/)

    if (NOT TARGET Autotalks::AtlkLocal)
        add_library(Autotalks::AtlkLocal SHARED IMPORTED)
        set_target_properties(Autotalks::AtlkLocal PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_LIBS_DIR}/libatlklocal_linux_u.so"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
        set_property(TARGET Autotalks::AtlkLocal APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES Autotalks::ToMcrypt Autotalks::ToMmath ${AUTOTALKS_OBJECTS} rt Autotalks::Optee)
        # target_link_libraries not working properly in CMake v3.5.1 used in Ubuntu 16.04
    endif()

endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Autotalks "Autotalks libraries not found" AUTOTALKS_ROOT)
