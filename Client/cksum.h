#ifndef CKSUM_H
#define CKSUM_H

#include <string>
#include <cstdint>

/**
 * @brief Calculate the CRC of a file
 *
 * @param fname the name of the file
 * @return the CRC of the file
 */
uint32_t readfileCRC(const std::string& fname);

#endif