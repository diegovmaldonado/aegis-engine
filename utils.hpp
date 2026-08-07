#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>

void log_error(const std::string& msg);

/** SHA-256 en hex de un string en memoria (no de un archivo -- para eso
 * ya existe sha256sum() en forensic.cpp). Usado por el log de auditoría
 * para identificar qué código se ejecutó sin guardar el código en sí. */
std::string sha256_hex(const std::string& data);

#endif
