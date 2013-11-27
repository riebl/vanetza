macro(_cohda_upload TARGET FILE DESTINATION)
    set(BANKLEUR_COHDA_UPLOAD_HOST "192.168.0.101" CACHE STRING "Upload to this Cohda box")
    set(upload_target "upload_${TARGET}")
    add_custom_target(${upload_target})
    foreach(host ${BANKLEUR_COHDA_UPLOAD_HOST})
        add_custom_target(${upload_target}_${host}
            COMMAND curl -T ${FILE} -u root: ftp://${host}/${DESTINATION})
        add_dependencies(${upload_target} ${upload_target}_${host})
        add_dependencies(${upload_target}_${host} ${TARGET})
    endforeach()
endmacro()

macro(cohda_upload_target TARGET DESTINATION)
    get_target_property(LOCAL_FILE ${TARGET} LOCATION)
    _cohda_upload(${TARGET} ${LOCAL_FILE} ${DESTINATION})
endmacro()

macro(cohda_upload_file TARGET FILE DESTINATION)
    add_custom_target(${TARGET} DEPENDS ${FILE})
    _cohda_upload(${TARGET} ${FILE} ${DESTINATION})
endmacro()

