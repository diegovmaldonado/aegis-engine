#ifndef FORENSIC_HPP
#define FORENSIC_HPP

#include <string>
#include <vector>

struct ForensicReport {
    std::string file_type;
    std::string mime_type;
    size_t size_bytes;
    std::string md5;
    std::string sha256;
    std::vector<std::string> iocs;           // IPs, URLs, correos
    std::vector<std::string> pe_sections;    // Nombres de secciones (PE)
    std::vector<std::string> elf_segments;   // Tipos de segmentos (ELF)
};

/**
 * Realiza análisis forense estático de un archivo.
 * @param path Ruta al archivo (debe existir y ser legible).
 * @return ForensicReport con la información extraída.
 */
ForensicReport analyze_file_static(const std::string& path);

#endif
