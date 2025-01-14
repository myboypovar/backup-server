#ifndef UTILS_H
#define UTILS_H

#include <string_view>
#include <string>
#include <vector>

/**
 * @brief Check if a string is a number
 *
 * @param s the string to be checked
 * @return true if the string is a number; false otherwise
 */
bool isNumber(const std::string_view& s);

/**
 * @brief convert a uuid in bytes format to a hex string
 *
 * @param the uuid in bytes format
 * @return the uuid in hex string format
 */
std::string uuidToHex(const std::vector<char>& uuid);

/**
 * @brief convert a hex string to a uuid in bytes format
 *
 * @param uuidHex the uuid in hex string format
 * @return the uuid in bytes format
 */
std::vector<char> hexToUuidBytes(const std::string& uuidHex);


#endif
