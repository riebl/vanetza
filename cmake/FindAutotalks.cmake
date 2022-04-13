if(NOT AUTOTALKS_CRATON)
    find_path(
        AUTOTALKS_ROOT
        NAMES "include/atlk/v2x_service.h"
        PATH_SUFFIXES "autotalks_secton_api"
        PATHS $ENV{HOME}
        CMAKE_FIND_ROOT_PATH_BOTH # Seems like this is not needed in newer CMake
    )

    set(AUTOTALKS_INCLUDE_DIRS ${AUTOTALKS_ROOT}/include ${AUTOTALKS_ROOT}/ref_src/include ${AUTOTALKS_ROOT}/depend/device/include)
    set(AUTOTALKS_LIBS_DIR ${AUTOTALKS_ROOT}/output.sec/x86/lib)
    set(AUTOTALKS_OBJ_DIR ${AUTOTALKS_ROOT}/output.sec/x86/obj)


    if (NOT TARGET Autotalks::AtlkRemote)
        add_library(Autotalks::AtlkRemote UNKNOWN IMPORTED)
        set_target_properties(Autotalks::AtlkRemote PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_LIBS_DIR}/libatlkremote_linux_u.so"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
    endif()

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

    set(AUTOTALKS_EXECUTABLES ${AUTOTALKS_OBJ_DIR}/target_type/target_type_remote.o ${AUTOTALKS_OBJ_DIR}/platform_type/platform_type_linux_u.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/remote/link_layer_remote.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/ipc/link_layer_ipc.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/tee/link_layer_tee_stub.o ${AUTOTALKS_OBJ_DIR}/link_layer/link_layer_interface.o ${AUTOTALKS_OBJ_DIR}/flash_reader/linux_u/remote/flash_reader_remote.o ${AUTOTALKS_OBJ_DIR}/ref_sys/ref_sys.o ${AUTOTALKS_OBJ_DIR}/ref_sys/ref_sys_logger.o ${AUTOTALKS_OBJ_DIR}/log_reader/log_reader.o ${AUTOTALKS_OBJ_DIR}/secure_hdif_crypto_layer/crypto_layer_ref_sys.o ${AUTOTALKS_OBJ_DIR}/secure_hdif_crypto_layer/crypto_layer_interface.o ${AUTOTALKS_OBJ_DIR}/secure_hdif_crypto_layer/crypto_lib_wrapper.o ${AUTOTALKS_OBJ_DIR}/secure_storage/secure_storage.o ${AUTOTALKS_OBJ_DIR}/time_sync/time_sync.o ${AUTOTALKS_OBJ_DIR}/time_sync/time_sync_poti.o ${AUTOTALKS_OBJ_DIR}/poti_lib/gnss/gnss.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_io.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_io_check.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_nav.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_parse.o ${AUTOTALKS_OBJ_DIR}/poti_lib/gnss/teseo/teseo.o ${AUTOTALKS_OBJ_DIR}/poti_lib/gnss/teseo/teseo_commands.o ${AUTOTALKS_OBJ_DIR}/poti_lib/coord/coord.o ${AUTOTALKS_OBJ_DIR}/poti_lib/periodic_alarm/periodic_alarm.o ${AUTOTALKS_OBJ_DIR}/poti_lib/api/poti_api.o)

else() # Craton device
    find_path(
        AUTOTALKS_ROOT
        NAMES "include/atlk/v2x_service.h"
        PATHS $ENV{HOME}
        PATH_SUFFIXES "autotalks_craton_api"
        CMAKE_FIND_ROOT_PATH_BOTH # Seems like this is not needed in newer CMake
    )

    set(AUTOTALKS_INCLUDE_DIRS "${AUTOTALKS_ROOT}/include" "${AUTOTALKS_ROOT}/ref_src/include" "${AUTOTALKS_ROOT}/depend/device/include")

    set(AUTOTALKS_LIBS_DIR ${AUTOTALKS_ROOT}/output.cr2_lnx/armv7-32/lib)
    set(AUTOTALKS_OBJ_DIR ${AUTOTALKS_ROOT}/output.cr2_lnx/armv7-32/obj)


    if (NOT TARGET Autotalks::AtlkLocal)
        add_library(Autotalks::AtlkLocal UNKNOWN IMPORTED)
        set_target_properties(Autotalks::AtlkLocal PROPERTIES
            IMPORTED_LOCATION "${AUTOTALKS_LIBS_DIR}/libatlklocal_linux_u.so"
            INTERFACE_INCLUDE_DIRECTORIES "${AUTOTALKS_INCLUDE_DIRS}")
    endif()

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

    set(AUTOTALKS_EXECUTABLES ${AUTOTALKS_OBJ_DIR}/target_type/target_type_local.o ${AUTOTALKS_OBJ_DIR}/platform_type/platform_type_linux_u.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/local/link_layer_local.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/ipc/link_layer_ipc.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/tee/static_list.o ${AUTOTALKS_OBJ_DIR}/link_layer/linux_u/tee/link_layer_tee.o ${AUTOTALKS_OBJ_DIR}/link_layer/link_layer_interface.o ${AUTOTALKS_OBJ_DIR}/flash_reader/linux_u/local/flash_reader_local.o ${AUTOTALKS_OBJ_DIR}/ref_sys/ref_sys.o ${AUTOTALKS_OBJ_DIR}/ref_sys/ref_sys_logger.o ${AUTOTALKS_OBJ_DIR}/log_reader/log_reader.o ${AUTOTALKS_OBJ_DIR}/secure_hdif_crypto_layer/crypto_layer_stubs.o ${AUTOTALKS_OBJ_DIR}/time_sync/time_sync.o ${AUTOTALKS_OBJ_DIR}/time_sync/time_sync_poti.o ${AUTOTALKS_OBJ_DIR}/poti_lib/gnss/gnss.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_io.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_io_check.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_nav.o ${AUTOTALKS_OBJ_DIR}/poti_lib/nmea/nmea_parse.o ${AUTOTALKS_OBJ_DIR}/poti_lib/gnss/teseo/teseo.o ${AUTOTALKS_OBJ_DIR}/poti_lib/gnss/teseo/teseo_commands.o ${AUTOTALKS_OBJ_DIR}/poti_lib/coord/coord.o ${AUTOTALKS_OBJ_DIR}/poti_lib/periodic_alarm/periodic_alarm.o ${AUTOTALKS_OBJ_DIR}/poti_lib/api/poti_api.o)


    foreach(dir ${AUTOTALKS_INCLUDE_DIRS})
        message("Directory: " ${dir})
    endforeach()
    
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Autotalks "Autotalks libraries not found" AUTOTALKS_ROOT)
