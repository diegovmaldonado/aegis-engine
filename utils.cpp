#include "utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

void log_error(const std::string& msg) {
    std::cerr << "[AEGIS ERROR] " << msg << std::endl;
}

std::string sha256_hex(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return ss.str();
}
