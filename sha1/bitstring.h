/*
 * Bitstring.h
 *
 *  Created on: 2009/10/11
 *      Author: Helder
 */

#ifndef BITSTRING_H_
#define BITSTRING_H_

#include <string>

using namespace std;

class bitstring {
private:
	bool* data;
	size_t sz;

public:
	class reference {
		private:
			friend class bitstring;

			bool* data;
			size_t p;

			reference();                                 // left undefined
		public:
			reference(bitstring& b, size_t pos);
			~reference();

			operator bool () const;                      // convert to bool
			reference& operator= ( bool x );             // assign from bool
			reference& operator= ( const reference& x ); // assign from bit
			reference& flip();                           // flip bit value
			bool operator~() const;                      // return inverse value
	};
	friend class reference;

	static const size_t	npos = static_cast<size_t>(-1);

	bitstring ( );

	bitstring ( size_t size );

	bitstring ( size_t size, unsigned long val );

	template<class charT, class traits, class Allocator>
	explicit bitstring ( size_t size, const basic_string<charT,traits,Allocator>& str,
	   typename basic_string<charT,traits,Allocator>::size_type pos = 0);

	template<class charT, class traits, class Allocator>
	bitstring ( size_t size, const basic_string<charT,traits,Allocator>& str,
	   typename basic_string<charT,traits,Allocator>::size_type pos,
	   typename basic_string<charT,traits,Allocator>::size_type n);

	/** bitstring member functions: ***/
	bitstring& operator&= (const bitstring& rhs);
	bitstring& operator|= (const bitstring& rhs);
	bitstring& operator^= (const bitstring& rhs);
	bitstring& operator<<= (size_t pos);
	bitstring& operator>>= (size_t pos);
	bitstring operator~() const;
	bitstring operator<<(size_t pos) const;
	bitstring operator>>(size_t pos) const;
	bool operator== (const bitstring& rhs) const;
	bool operator!= (const bitstring& rhs) const;

	/*** global functions: ***/
	friend bitstring operator& (const bitstring& lhs, const bitstring& rhs);
	friend bitstring operator| (const bitstring& lhs, const bitstring& rhs);
	friend bitstring operator^ (const bitstring& lhs, const bitstring& rhs);

	/*** iostream global functions (extraction/insertion): ***/
	template<class charT, class traits>
	  friend basic_istream<charT, traits>&
	    operator>> (basic_istream<charT,traits>& is, bitstring& rhs);
	template<class charT, class traits>
	  friend basic_ostream<charT, traits>&
	    operator<< (basic_ostream<charT,traits>& os, bitstring& rhs);

    bool operator[] ( size_t pos ) const;
    reference operator[] ( size_t pos );

    bool get(int n);

    bitstring& set ( );
    bitstring& set ( size_t pos, bool val = true );

    bitstring& reset ( );
    bitstring& reset ( size_t pos );

    bitstring& flip ( );
    bitstring& flip ( size_t pos );

    unsigned long to_ulong ( ) const;

    /*template <class charT, class traits, class Allocator>
      basic_string<charT,traits,Allocator> to_string() const;*/

    string to_string() const;

    size_t count ( );

    size_t size() const;

    bool test ( size_t pos ) const;

    bool any ( ) const;

    void print();

    bool none ( ) const;

    bitstring subbits(size_t pos = 0, size_t n = npos);
};

#endif /* BITSTRING_H_ */
