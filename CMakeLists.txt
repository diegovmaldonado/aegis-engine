cmake_minimum_required(VERSION 3.15)
project(aegis_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Detección automática de sistema operativo ---
# Esto es lo que realmente puede "detectar el SO automáticamente": el
# SISTEMA DE BUILD elige qué archivos compilar. Un binario compilado ya
# quedó fijado a un SO (un .exe no corre en Linux ni un ELF en Windows),
# así que la detección real y útil pasa en este paso, no en tiempo de
# ejecución del binario final.

set(COMMON_SOURCES
    main.cpp
    forensic.cpp
    utils.cpp
)

add_executable(aegis-engine ${COMMON_SOURCES})
target_include_directories(aegis-engine PRIVATE ${CMAKE_SOURCE_DIR} src)

if (WIN32)
    message(STATUS "Compilando para Windows: envoltorio WSL2 (reutiliza el binario Linux ya probado)")
    # sandbox_windows_wsl.cpp: RECOMENDADO -- delega en el binario de Linux
    # ya verificado, corriendo dentro de la VM de WSL2. Ver INFORME_ESTADO.md.
    # sandbox_windows.cpp: alternativa nativa con Job Objects (memoria/CPU/
    # privilegios sí, pero SIN aislamiento de filesystem/red equivalente a
    # namespaces -- y sin probar, ver el informe). Para usarla en vez de la
    # de WSL2, cambiar la línea de abajo.
    target_sources(aegis-engine PRIVATE src/sandbox_windows_wsl.cpp)
    target_link_libraries(aegis-engine PRIVATE ws2_32 psapi advapi32)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(aegis-engine PRIVATE OpenSSL::Crypto)

elseif (UNIX AND NOT APPLE)
    message(STATUS "Compilando para Linux: namespaces + libseccomp + cgroups v2")
    target_sources(aegis-engine PRIVATE
        src/sandbox_linux.cpp
        src/seccomp_linux.cpp
        src/cgroups_linux.cpp
    )
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SECCOMP REQUIRED libseccomp)
    find_package(OpenSSL REQUIRED)

    target_include_directories(aegis-engine PRIVATE ${SECCOMP_INCLUDE_DIRS})
    target_link_libraries(aegis-engine PRIVATE
        ${SECCOMP_LIBRARIES} OpenSSL::Crypto pthread)

else()
    message(FATAL_ERROR "AEGIS Engine no soporta esta plataforma (macOS incluido) todavía. "
                         "macOS no tiene seccomp ni cgroups v2 -- requeriría un backend "
                         "propio con Sandbox.framework/Endpoint Security, no incluido aquí.")
endif()

target_compile_options(aegis-engine PRIVATE -O2)
