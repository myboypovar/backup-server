#ifndef ENDIAN_H
#define ENDIAN_H

#include <cstdint>
#include <type_traits>
#include <boost/endian/conversion.hpp>


/*
* @brief Functions for converting between big and little endian
*/
namespace EndianConverter 
{
	/**
	* @brief Convert a value to litte endian
	* 
	* @tparam T the type of the value
	* @param value the value to be converted
	*/
	template <typename T>
	void toLittleEndian(T& value)
	{
		static_assert(std::is_integral_v<T>, "Only integral types are supported");
		value = boost::endian::native_to_little(value);
	}

	/**
	* @brief Check if the system is big endian
	* 
	* @return true if the system is big endian; false if little endian
	*/
	inline bool isBigEndian()
	{
		return boost::endian::order::native == boost::endian::order::big;
	}
}

#endif // ENDIAN_H
