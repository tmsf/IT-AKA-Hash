/*
 * Bitstring.cpp
 *
 *  Created on: 2009/10/11
 *      Author: Helder
 */

#include <iostream>
#include <climits>
#include <stdexcept>

using namespace std;

#include "bitstring.h"

bitstring::bitstring() {
	data = NULL;
	sz = 0;
}

bitstring::bitstring(size_t size) {
	data = new bool[size];
	sz = size;
}

bitstring::bitstring(size_t size, unsigned long val) {
	data = new bool[size];
	sz = size;
	int aux = 32;

	for(size_t i=0; i<size; i++){

		data[i] = val % 2;
		val /= 2;

		aux--;
		if(aux == 0) {
			val = rand();
			aux = 32;
		}
	}
}

template<class charT, class traits, class Allocator>
bitstring::bitstring ( size_t size, const basic_string<charT,traits,Allocator>& str,
   typename basic_string<charT,traits,Allocator>::size_type pos) {
	bitstring(size, str, pos, basic_string<charT,traits,Allocator>::npos);
}

template<class charT, class traits, class Allocator>
bitstring::bitstring ( size_t size, const basic_string<charT,traits,Allocator>& str,
   typename basic_string<charT,traits,Allocator>::size_type pos,
   typename basic_string<charT,traits,Allocator>::size_type n) {
	if (pos > str.size()) {
		throw out_of_range("initial position not valid");
	}

	data = new bool[size];
	sz = size;

	const size_t nbits = std::min(size, std::min(n, str.size() - pos));
	for (size_t i = 0; i < nbits; i++)
	{
		switch(str[pos + nbits - i - 1])
		{
			case '0':
				break;
			case '1':
				set(i);
				break;
			default:
				throw invalid_argument("invalid string format");
		}
	}
}

/** bitstring member functions: ***/
bitstring& bitstring::operator&= (const bitstring& rhs) {
	if (rhs.size() != sz) {
		throw invalid_argument("invalid rhs size");
	}

	for (size_t i = 0; i < sz; i++) {
		data[i] &= rhs.data[i];
	}

	return *this;
}

bitstring& bitstring::operator|= (const bitstring& rhs) {
	if (rhs.size() != sz) {
		throw invalid_argument("invalid rhs size");
	}

	for (size_t i = 0; i < sz; i++) {
		data[i] |= rhs.data[i];
	}

	return *this;
}

bitstring& bitstring::operator^= (const bitstring& rhs) {
	if (rhs.size() != sz) {
		throw invalid_argument("invalid rhs size");
	}

	for (size_t i = 0; i < sz; i++) {
		data[i] ^= rhs.data[i];
	}

	return *this;
}

bitstring& bitstring::operator<<= (size_t pos) {
	int i;

	for (i = sz - 1; i >= (int)pos; i--) {
		data[i] = data[i - pos];
	}

	for (; i >= 0; i--) {
		data[i] = false;
	}

	return *this;
}

bitstring& bitstring::operator>>= (size_t pos) {
	int i;

	for (i = 0; i < (int)sz - (int)pos; i++) {
		data[i] = data[i + pos];
	}

	for (; i < (int)sz; i++) {
		data[i] = false;
	}

	return *this;
}

bitstring bitstring::operator~() const {
	return bitstring(*this).flip();
}

bitstring bitstring::operator<<(size_t pos) const {
	return bitstring(*this) <<= pos;
}

bitstring bitstring::operator>>(size_t pos) const {
	return bitstring(*this) >>= pos;;
}

bool bitstring::operator== (const bitstring& rhs) const {
	if (rhs.size() != sz) {
		return false;
	}

	for (int i = 0; i < (int)sz; i++) {
		if (data[i] != rhs.data[i]) {
			return false;
		}
	}

	return true;
}

bool bitstring::operator!= (const bitstring& rhs) const {
	return !(*this == rhs);
}

/*** global functions: ***/
bitstring operator& (const bitstring& lhs, const bitstring& rhs) {
	bitstring result(lhs);

	result &= rhs;

	return result;
}

bitstring operator| (const bitstring& lhs, const bitstring& rhs) {
	bitstring result(lhs);

	result |= rhs;

	return result;
}

bitstring operator^ (const bitstring& lhs, const bitstring& rhs)  {
	bitstring result(lhs);

	result ^= rhs;

	return result;
}

/*** iostream global functions (extraction/insertion): ***/
template<class charT, class traits>
  basic_istream<charT, traits>&
    operator>> (basic_istream<charT,traits>& is, bitstring& rhs) {
	typedef typename traits::char_type char_type;
	basic_string<charT, traits> tmp;
	tmp.reserve(rhs.sz);

	ios_base::iostate state = ios_base::goodbit;
	typename basic_istream<charT, traits>::sentry sentry(is);
	if (sentry)
	{
		try
		{
			basic_streambuf<charT, traits>*buf = is.rdbuf();
			const char_type zero =is.widen('0');
			const char_type one = is.widen('1');

			for (size_t i = 0; i < rhs.sz; i++)
			{
				static typename traits::int_type eof = traits::eof();

				typename traits::int_type c1 = buf->sbumpc();
				if (traits::eq_int_type(c1, eof))
				{
					state |= ios_base::eofbit;
					break;
				}
				else
				{
					char_type c2 = traits::to_char_type(c1);
					if (c2 == zero) {
						tmp.push_back('0');
					}
					else if (c2 == one) {
						tmp.push_back('1');
					}
					else if (traits::eq_int_type(buf->sputbackc(c2), eof))
					{
						state |= ios_base::failbit;
						break;
					}
				}
			}
		}
		catch (...) {
			is.setstate(ios_base::badbit);
		}
	}

	if (tmp.empty() && rhs.sz) {
		state |= ios_base::failbit;
	}
	else {
		rhs = bitstring(rhs.sz, tmp, static_cast<size_t>(0), rhs.sz);
	}

	if (state) {
		is.setstate(state);
	}

	return is;
}

template<class charT, class traits>
  basic_ostream<charT, traits>&
    operator<< (basic_ostream<charT,traits>& os, bitstring& rhs) {
	basic_string<charT, traits> tmp = rhs.to_string();

	return os << tmp;
}

bool bitstring::operator[] ( size_t pos ) const {
	return data[pos];
}

bitstring::reference bitstring::operator[] ( size_t pos ) {
	return bitstring::reference(*this, pos);
}


bool bitstring::get(int n){
	return data[n];
}

bitstring& bitstring::set ( ) {
	for (size_t i = 0; i < sz; i++) {
		data[i] = true;
	}

	return *this;
}

bitstring& bitstring::set ( size_t pos, bool val ) {
	if (pos >= sz) {
		throw out_of_range("position is out of range");
	}

	data[pos] = val;

	return *this;
}

bitstring& bitstring::reset ( ) {
	for (size_t i = 0; i < sz; i++) {
		data[i] = false;
	}

	return *this;
}

bitstring& bitstring::reset ( size_t pos ) {
	if (pos >= sz) {
		throw out_of_range("position is out of range");
	}

	data[pos] = false;

	return *this;
}

bitstring& bitstring::flip ( ) {
	for (size_t i = 0; i < sz; i++) {
		data[i] = !data[i];
	}

	return *this;
}

bitstring& bitstring::flip ( size_t pos ) {
	if (pos >= sz) {
		throw out_of_range("pos is out of range");
	}

	data[pos] = !data[pos];

	return *this;
}

unsigned long bitstring::to_ulong ( ) const {
	if (sz > sizeof(unsigned long) * CHAR_BIT) {
		throw overflow_error("size of bitstring is too long");
	}

	unsigned long result = 0;

	for (size_t i = 0; i < sz; i++) {
		if (data[i]) {
			result |= 1 << i;
		}
	}

	return result;
}

/*template <class charT, class traits, class Allocator>
  basic_string<charT,traits,Allocator> bitstring::to_string() const {
	basic_string<charT,traits,Allocator> result;

	result.assign(sz, '0');
	for (size_t i = 0; i < sz; i++) {
		if (data[i]) {
			result[sz - 1 - i] = '1';
		}
	}

	return result;
}*/

string bitstring::to_string() const {
	string result;

	result.assign(sz, '0');
	for (size_t i = 0; i < sz; i++) {
		if (data[i]) {
			result[sz - 1 - i] = '1';
		}
	}

	return result;
}

size_t bitstring::count ( ) {
	size_t result = 0;

	for (size_t i = 0; i < sz; i++) {
		if (data[i]) {
			result++;
		}
	}

	return result;
}

size_t bitstring::size() const {
	return sz;
}

bool bitstring::test ( size_t pos ) const {
	if (pos >= sz) {
		throw out_of_range("position is out of range");
	}

	return data[pos];
}

bool bitstring::any ( ) const {
	for (size_t i = 0; i < sz; i++) {
		if (data[i]) {
			return true;
		}
	}

	return false;
}

bool bitstring::none ( ) const {
	return !any();
}
void bitstring::print(){
	cout << "[";
	for(size_t i=0; i<sz; i++){
		if(data[i]) cout << "1";
		else cout << "0";
	}
	cout << "]";
}

bitstring bitstring::subbits(size_t pos, size_t n) {
	if (n == npos) {
		n = sz - pos;
	}

	if (pos >= sz) {
		throw out_of_range("pos is out of range");
	}
	if (pos + n > sz) {
		throw out_of_range("pos + n is out of range");
	}

	bitstring result(n);

	for (size_t i = 0; i < n; i++) {
		result[i] = data[pos + i];
	}

	return result;
}

/************ bitstring::refernce ************/

bitstring::reference::reference(bitstring& b, size_t pos) {
	data = b.data;
	p = pos;
}

bitstring::reference::~reference() {
}

bitstring::reference::operator bool () const {
	return data[p];
}

bitstring::reference& bitstring::reference::operator= ( bool x ) {
	data[p] = x;

	return *this;
}

bitstring::reference& bitstring::reference::operator= ( const bitstring::reference& x ) {
	data[p] = x.data[x.p];

	return *this;
}

bitstring::reference& bitstring::reference::flip() {
	data[p] = !data[p];

	return *this;
}

bool bitstring::reference::operator~() const {
	return !data[p];
}
