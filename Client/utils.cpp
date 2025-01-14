#include "utils.h"

#include <iostream>
#include <algorithm>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/string_generator.hpp>


bool isNumber(const std::string_view& s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}


std::string uuidToHex(const std::vector<char>& uuid) {
    if (uuid.size() != 16) {
        throw std::invalid_argument("UUID must be 16 bytes long");
    }

    // Create a UUID object from the vector
    boost::uuids::uuid boostUuid;
    std::copy(uuid.begin(), uuid.end(), boostUuid.begin());

    // Convert the UUID to a string (hex format)
    return boost::uuids::to_string(boostUuid);
}

std::vector<char> hexToUuidBytes(const std::string& uuidHex) {
    // Use Boost's string_generator to convert from string to uuid
    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(uuidHex);

    // Convert the UUID to a vector of bytes
    std::vector<char> uuidBytes(uuid.begin(), uuid.end());

    return uuidBytes;
}