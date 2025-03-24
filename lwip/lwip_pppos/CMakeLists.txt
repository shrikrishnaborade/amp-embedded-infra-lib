add_library(lwip.ppp STATIC)

target_include_directories(lwip.ppp PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../../../..>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(lwip.ppp PUBLIC
    hal.interfaces
    infra.timer
    infra.util
    hal_ti.cortex
    lwip.lwip
    services.network
    ti.sdk_cc35xx
    cellular_connectivity.communications
)

target_sources(lwip.ppp PRIVATE
    DialUpModemStatus.hpp
    PppInterface.hpp
    DialUpModem.hpp
    DialUpModem.cpp
    PppFacade.hpp
    PppFacade.cpp
)
