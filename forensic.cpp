#include "forensic.hpp"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <regex>
#include <algorithm>
#include <cstdint>
#include <iomanip>

static std::string md5sum(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    MD5_CTX ctx; MD5_Init(&ctx);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)).gcount() > 0) {
        MD5_Update(&ctx, buffer, file.gcount());
    }
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &ctx);
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return ss.str();
}

static std::string sha256sum(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";
    SHA256_CTX ctx; SHA256_Init(&ctx);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)).gcount() > 0) {
        SHA256_Update(&ctx, buffer, file.gcount());
    }
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &ctx);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return ss.str();
}

// Reemplaza el popen("file --mime-type ...") del original, que solo
// funciona en Linux (y además ejecuta un proceso externo -- una llamada
// menos segura dentro de una herramienta forense). Detección propia por
// magic bytes: portable a Windows y no depende de binarios del sistema.
static std::string detect_mime_by_magic(const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) return "application/octet-stream";
    unsigned char h[8] = {0};
    f.read(reinterpret_cast<char*>(h), sizeof(h));

    if (h[0]==0x4D && h[1]==0x5A) return "application/x-msdownload";       // MZ (PE/EXE)
    if (h[0]==0x7F && h[1]=='E' && h[2]=='L' && h[3]=='F') return "application/x-elf";
    if (h[0]==0x25 && h[1]=='P' && h[2]=='D' && h[3]=='F') return "application/pdf";
    if (h[0]==0x50 && h[1]=='K') return "application/zip";                 // ZIP/DOCX/JAR
    if (h[0]==0x89 && h[1]=='P' && h[2]=='N' && h[3]=='G') return "image/png";
    if (h[0]==0xFF && h[1]==0xD8) return "image/jpeg";
    if (h[0]=='G' && h[1]=='I' && h[2]=='F') return "image/gif";
    if (h[0]==0x1F && h[1]==0x8B) return "application/gzip";

    // Heurística de texto: si los primeros bytes son todos imprimibles/ASCII.
    bool looks_text = true;
    for (int i = 0; i < 8; ++i) {
        if (h[i] != 0 && (h[i] < 0x09 || (h[i] > 0x0D && h[i] < 0x20) )) {
            looks_text = false; break;
        }
    }
    return looks_text ? "text/plain" : "application/octet-stream";
}

static std::vector<std::string> extract_iocs(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    std::vector<std::string> iocs;
    if (!file) return iocs;
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    std::regex ipv4(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
    std::regex url(R"(\bhttps?://[^\s\"']+)");
    std::regex email(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)");

    auto add_matches = [&](const std::regex& re) {
        auto it = std::sregex_iterator(content.begin(), content.end(), re);
        auto end = std::sregex_iterator();
        while (it != end) { iocs.push_back(it->str()); ++it; }
    };
    add_matches(ipv4); add_matches(url); add_matches(email);

    std::sort(iocs.begin(), iocs.end());
    iocs.erase(std::unique(iocs.begin(), iocs.end()), iocs.end());
    return iocs;
}

static std::vector<std::string> analyze_pe(const std::string& filepath) {
    std::vector<std::string> sections;
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return sections;
    char mz[2]; file.read(mz, 2);
    if (mz[0] != 'M' || mz[1] != 'Z') return sections;
    file.seekg(0x3C); int32_t pe_offset; file.read(reinterpret_cast<char*>(&pe_offset), 4);
    if (!file) return sections;
    file.seekg(pe_offset); char sig[4]; file.read(sig, 4);
    if (sig[0]!='P'||sig[1]!='E'||sig[2]!=0||sig[3]!=0) return sections;
    file.seekg(pe_offset + 6); uint16_t num_sections;
    file.read(reinterpret_cast<char*>(&num_sections), 2);
    if (!file) return sections;
    file.seekg(pe_offset + 20); uint16_t opt_header_size;
    file.read(reinterpret_cast<char*>(&opt_header_size), 2);
    int section_table_offset = pe_offset + 24 + opt_header_size;
    for (int i = 0; i < num_sections; ++i) {
        file.seekg(section_table_offset + i * 40);
        char name[9] = {0}; file.read(name, 8);
        sections.push_back(std::string(name));
    }
    return sections;
}

static std::vector<std::string> analyze_elf(const std::string& filepath) {
    std::vector<std::string> segments;
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return segments;
    char magic[4]; file.read(magic, 4);
    if ((unsigned char)magic[0]!=0x7F||magic[1]!='E'||magic[2]!='L'||magic[3]!='F') return segments;
    char ei_class; file.seekg(4); file.read(&ei_class, 1);
    if (ei_class == 2) {
        file.seekg(0x20); uint64_t phoff; file.read(reinterpret_cast<char*>(&phoff), 8);
        uint16_t phnum; file.read(reinterpret_cast<char*>(&phnum), 2);
        for (int i = 0; i < phnum; ++i) {
            file.seekg(phoff + i * 56);
            uint32_t p_type; file.read(reinterpret_cast<char*>(&p_type), 4);
            switch (p_type) {
                case 1: segments.push_back("LOAD"); break;
                case 2: segments.push_back("DYNAMIC"); break;
                case 3: segments.push_back("INTERP"); break;
                case 4: segments.push_back("NOTE"); break;
                case 6: segments.push_back("PHDR"); break;
                case 0x6474e550: segments.push_back("GNU_EH_FRAME"); break;
                case 0x6474e551: segments.push_back("GNU_STACK"); break;
                case 0x6474e552: segments.push_back("GNU_RELRO"); break;
                default: segments.push_back("UNKNOWN"); break;
            }
        }
    }
    return segments;
}

// --- Restricción a carpeta de cuarentena ---
// analyze_file_static() corre SIN sandbox -- directamente en el proceso
// aegis-engine, sin pivot_root ni namespaces (a diferencia de
// execute_python). Antes de esto, aceptaba CUALQUIER ruta del sistema:
// quien pudiera llamar a esta operación con una ruta arbitraria podía
// leer cualquier archivo accesible al usuario con el que corre el motor
// -- tamaño, hashes, y contenido vía la extracción de IOCs (IPs/URLs/
// emails encontrados adentro). No es un problema de "análisis forense
// mal hecho", es una lectura de archivo arbitraria disfrazada de feature.
//
// Ahora se exige que la ruta resuelva (symlinks y ".." incluidos, vía
// realpath) dentro de un directorio de cuarentena designado -- por
// defecto /var/lib/aegis-engine/quarantine, configurable con la variable
// de entorno AEGIS_QUARANTINE_DIR. Fail-closed: si la cuarentena ni
// siquiera existe, se rechaza todo en vez de permitir todo.
//
// Riesgo residual, documentado a propósito y no cerrado en este cambio:
// hay una ventana TOCTOU entre este chequeo y la apertura real del
// archivo más abajo (varias funciones abren su propio std::ifstream sobre
// la misma ruta). Cerrar eso del todo requeriría abrir el archivo UNA
// vez con O_NOFOLLOW y pasar el mismo fd a las 6 funciones de análisis
// (md5sum, sha256sum, detect_mime_by_magic, extract_iocs, analyze_pe,
// analyze_elf) en vez de que cada una reabra la ruta -- es un refactor
// más grande que merece su propia revisión, no un parche apurado.
static bool resolver_dentro_de_cuarentena(const std::string& path, std::string& resuelto_out) {
    const char* qdir_env = std::getenv("AEGIS_QUARANTINE_DIR");
    std::string qdir = qdir_env ? qdir_env : "/var/lib/aegis-engine/quarantine";

    char* resuelto_c = realpath(path.c_str(), nullptr);
    if (!resuelto_c) return false; // no existe / no se pudo resolver
    std::string resuelto(resuelto_c);
    free(resuelto_c);

    char* qdir_resuelto_c = realpath(qdir.c_str(), nullptr);
    if (!qdir_resuelto_c) return false; // la cuarentena ni existe -- fail closed
    std::string qdir_resuelto(qdir_resuelto_c);
    free(qdir_resuelto_c);

    resuelto_out = resuelto;
    if (resuelto == qdir_resuelto) return true;
    // Comparación de PREFIJO DE RUTA con "/" al final, no de substring --
    // así "/var/.../quarantine-evil" no cuela como si fuera un archivo
    // "dentro" de "/var/.../quarantine".
    return resuelto.compare(0, qdir_resuelto.size() + 1, qdir_resuelto + "/") == 0;
}

ForensicReport analyze_file_static(const std::string& path) {
    std::string resolved;
    if (!resolver_dentro_de_cuarentena(path, resolved)) {
        throw std::runtime_error(
            "Ruta rechazada: analyze_file_static solo puede leer archivos "
            "dentro de la carpeta de cuarentena (AEGIS_QUARANTINE_DIR, por "
            "defecto /var/lib/aegis-engine/quarantine). Ruta pedida: " + path
        );
    }

    ForensicReport report;
    struct stat st;
    if (stat(resolved.c_str(), &st) != 0) {
        throw std::runtime_error("No se puede acceder al archivo: " + path);
    }
    report.size_bytes = st.st_size;
    report.mime_type = detect_mime_by_magic(resolved);
    report.file_type = report.mime_type;
    report.md5 = md5sum(resolved);
    report.sha256 = sha256sum(resolved);
    report.iocs = extract_iocs(resolved);

    if (report.mime_type == "application/x-msdownload") {
        report.pe_sections = analyze_pe(resolved);
    }
    report.elf_segments = analyze_elf(resolved);
    return report;
}
