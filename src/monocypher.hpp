// Monocypher version __git__
//
// This file is dual-licensed.  Choose whichever licence you want from
// the two licences listed below.
//
// The first licence is a regular 2-clause BSD licence.  The second licence
// is the CC-0 from Creative Commons. It is intended to release Monocypher
// to the public domain.  The BSD licence serves as a fallback option.
//
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
//
// ------------------------------------------------------------------------
//
// Copyright (c) 2025, Joshua Nabors
// All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ------------------------------------------------------------------------
//
// Written in 2025 by Joshua Nabors
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#ifndef MONOCYPHER_HPP
#define MONOCYPHER_HPP

///	C++ bindings to monocypher
///
///	Arguments passed with swap semantics (type&& arg) are wiped upon return of the function;
///	make a copy manually if you want to explicitly reuse a key for multiple calls. This is
///	an intentional design decision to prevent heap attacks from finding discarded keys in
///	uninitialized memory. (Initialized memory is fair game)
///
///	Hash objects are intentionally immutable and will copy themselves on updating instead of
///	mutating the underlying object. This does involve a few extra copies as overhead, but
///	the end result is that we get to make the entirety of the class immutable, which makes it's
///	usage just a little bit more straightforwards. Hopefully.

#include <array>
#include <optional>
#include <vector>
#include <memory>

#ifdef MONOCYPHER_CPP_NAMESPACE
namespace MONOCYPHER_CPP_NAMESPACE {

#define MONOCYPHER_CPP_NAMESPACE_PLEASE_CLOSE_KTHX
#undef MONOCYPHER_CPP_NAMESPACE
#endif

	namespace detail {
		#include "monocypher.h"
		#include "monocypher-ed25519.h"
	}

	namespace constant_time_arrays {
		///	@brief Constant-time verification for 16 byte arrays
		inline bool operator==(const ::std::array<uint8_t, 16>& lhs, const std::array<uint8_t, 16>& rhs) noexcept {
			return detail::crypto_verify16( lhs.data(), rhs.data() ) == 0;
		}

		///	@brief Constant-time verification for 16 byte arrays
		inline bool operator!=(const ::std::array<uint8_t, 16>& lhs, const std::array<uint8_t, 16>& rhs) noexcept {
			return detail::crypto_verify16( lhs.data(), rhs.data() ) != 0;
		}

		///	@brief Constant-time verification for 32 byte arrays
		inline bool operator==(const std::array<uint8_t, 32>& lhs, const std::array<uint8_t, 32>& rhs) noexcept {
			return detail::crypto_verify32( lhs.data(), rhs.data() ) == 0;
		}

		///	@brief Constant-time verification for 32 byte arrays
		inline bool operator!=(const std::array<uint8_t, 32>& lhs, const std::array<uint8_t, 32>& rhs) noexcept {
			return detail::crypto_verify32( lhs.data(), rhs.data() ) != 0;
		}

		///	@brief Constant-time verification for 64 byte arrays
		inline bool operator==(const ::std::array<uint8_t, 64>& lhs, const ::std::array<uint8_t, 64>& rhs) noexcept {
			return detail::crypto_verify64( lhs.data(), rhs.data() ) == 0;
		}

		inline bool operator!=(const ::std::array<uint8_t, 64>& lhs, const ::std::array<uint8_t, 64>& rhs) noexcept {
			return detail::crypto_verify64( lhs.data(), rhs.data() ) != 0;
		}
	}


	///	@brief A wrapper around an object that enforces it's zeroization on scope exit
	template<typename Type>
	class secret_box {
		Type _self = {};
	public:
		secret_box() noexcept = default;

		explicit secret_box( Type&& self ) noexcept
			: _self( std::move(self) ) {
			detail::crypto_wipe( &self, sizeof(self) );
		};

		Type* operator->() noexcept {
			return &_self;
		}

		Type* object() noexcept {
			return &_self;
		}

		operator Type*() noexcept {
			return &_self;
		}

		~secret_box() noexcept {
			detail::crypto_wipe( &_self, sizeof(Type) );
		}
	};

	///	@brief A variant of std::array that wipes itself when it leaves scope.
	///
	///	This is internally used on owning copies of secrets within the Monocypher bindings
	///	to prevent keys from being left around memory during destruction.
	template<typename Type, size_t Size>
	class secret_array : public ::std::array<Type, Size> {
	public:
		secret_array() noexcept
			: ::std::array<Type, Size>{ 0 }
		{}

		explicit secret_array( ::std::array<Type, Size>&& other ) noexcept
			: ::std::array<Type, Size>( std::move( other ) ) {
			detail::crypto_wipe( other._Elems, sizeof(other._Elems) );
		}

		~secret_array() noexcept {
			detail::crypto_wipe( this->_Elems, sizeof(this->_Elems) );
		}
	};

	///	@brief A variant of std::vector that wipes itself when it leaves scope.
	///
	///	This is internally used on owning copies of secrets within the Monocypher bindings
	///	to prevent keys from being left around memory during destruction.
	template<typename Type, size_t MaxSize = ::std::numeric_limits<size_t>::max()>
	class secret_vector : public ::std::vector<Type> {
	public:
		secret_vector() noexcept
			: ::std::vector<Type>{}
		{}

		explicit secret_vector( ::std::vector<Type>&& other ) noexcept
			: ::std::vector<Type>( ::std::min(MaxSize, other.size()), Type() ) {
			for (size_t i = 0; i < this->size(); ++i)
				::std::swap(this->data()[i], other[i]);

			detail::crypto_wipe( other.data(), other.capacity() * sizeof(Type) );
		}

		~secret_vector() noexcept {
			detail::crypto_wipe( this->data(), this->capacity() * sizeof(Type) );
		}
	};

	///	@brief Fast authenticated encryption with XChaCha20-Poly1305
	class aead {
		const secret_array<uint8_t, 32> _secret_key = {};
	public:
		///	@brief Construct a xchacha-poly1305 instance by taking ownership of a secret key.
		///
		///	The array passed into the constructor will be wiped, to prevent copies of the key
		///	from floating around in memory. This object wipes itself on destruction.
		explicit aead( ::std::array<uint8_t, 32>&& secret_key) noexcept
			: _secret_key{ ::std::move( secret_key ) }
		{}

		struct ciphertext_result {
			::std::vector<uint8_t> ciphertext;
			::std::array<uint8_t, 16> mac;
		};

		///	@brief Encrypts the plaintext and then creates an authentication code for ad || ciphertext
		///	@warning YOU MUST ALWAYS USE A UNIQUE NONCE. NONCE REUSE WEAKENS THE SCHEME.
		///	Nonce Reuse - Not Even Once!™
		///
		///	@param plaintext The plaintext data to be encrypted
		///	@param associated_data The unencrypted associated data to be used as a form of header
		///	@param nonce The unique nonce for this message. Reuse allows attackers to break the scheme.
		[[nodiscard]] ciphertext_result lock( const ::std::vector<uint8_t>& plaintext, const ::std::vector<uint8_t>& associated_data,
			const ::std::array<uint8_t, 24>& nonce ) const noexcept {
			ciphertext_result result = {
				::std::vector<uint8_t>( plaintext.size() ),
				::std::array<uint8_t, 16>()
			};

			detail::crypto_aead_lock( result.ciphertext.data(), result.mac.data(), _secret_key.data(), nonce.data(),
				associated_data.data(), associated_data.size(), plaintext.data(), plaintext.size());

			return result;
		}

		///	@brief Authenticates the ad || ciphertext and then decrypts the ciphertext.
		///	@warning Poly1305 is not key committing; ensure you aren't vulnerable to invisible salamanders attacks.
		///
		///	@param ciphertext The ciphertext data to be encrypted
		///	@param associated_data The unencrypted authenticated associated data to be used as a form of header
		///	@param nonce The unique nonce for this message. Reuse allows attackers to break the scheme.
		///	@param mac The authentication code produced by a call to aead::lock
		[[nodiscard]] ::std::optional<std::vector<uint8_t>> unlock( const ::std::vector<uint8_t>& ciphertext, const ::std::vector<uint8_t>& associated_data,
			const ::std::array<uint8_t, 24>& nonce, const ::std::array<uint8_t, 16>& mac ) const noexcept {
			::std::vector<uint8_t> plaintext = ::std::vector<uint8_t>( ciphertext.size() );

			if (detail::crypto_aead_unlock( plaintext.data(), mac.data(), _secret_key.data(), nonce.data(),
				associated_data.data(), associated_data.size(), ciphertext.data(), ciphertext.size()) != 0) {
				//	If the value is not zero, then this is a failure
				return ::std::nullopt;
			}

			return plaintext;
		}
	};

	///	@brief Fast unauthenticated stream cipher
	class chacha20 {
		const secret_array<uint8_t, 32> _secret_key = {};
	public:
		///	@brief Construct a chacha20 instance by taking ownership of a secret key.
		///
		///	The array passed into the constructor will be wiped, to prevent copies of the key
		///	from floating around in memory. This object wipes itself on destruction.
		explicit chacha20( ::std::array<uint8_t, 32>&& secret_key) noexcept
			: _secret_key{ ::std::move( secret_key ) }
		{}

		///	@brief XChaCha20 with the specified nonce
		///
		///	@param text The (cipher/plain)text
		///	@param nonce The nonce
		///	@param counter The counter to begin the stream with, if any.
		///	@returns The (cipher/plain)text (de/en)crypted with the ChaCha20 stream.
		[[nodiscard]] ::std::vector<uint8_t> xchacha( const ::std::vector<uint8_t>& text, const ::std::array<uint8_t, 24>& nonce, uint64_t counter = 0 ) const noexcept {
			::std::vector<uint8_t> crypt_text = { text };
			detail::crypto_chacha20_x( crypt_text.data(), text.data(), text.size(), _secret_key.data(), nonce.data(), counter );

			return crypt_text;
		}

		///	@brief HChaCha20 with the specified nonce
		///
		///	HChaCha is an optimized PRF for use within XChaCha20.
		[[nodiscard]] ::std::array<uint8_t, 32> hchacha( const ::std::array<uint8_t, 16>& nonce ) const noexcept {
			::std::array<uint8_t, 32> output = {};
			detail::crypto_chacha20_h( output.data(), _secret_key.data(), nonce.data() );

			return output;
		}

		///	@brief DJB's original ChaCha20 stream cipher. 64 bits of nonce and 64 bits of counter
		///
		///	The nonce should not be random. If you need random nonces, use XChaCha20.
		///
		///	@param text The (cipher/plain)text
		///	@param nonce The nonce
		///	@param counter The counter to begin the stream with, if any.
		///	@returns The (cipher/plain)text (de/en)crypted with the ChaCha20 stream.
		[[nodiscard]] ::std::vector<uint8_t> djb_chacha( const ::std::vector<uint8_t>& text, const ::std::array<uint8_t, 8>& nonce, uint64_t counter = 0 ) const noexcept {
			::std::vector<uint8_t> crypt_text = { text };
			detail::crypto_chacha20_djb( crypt_text.data(), text.data(), text.size(), _secret_key.data(), nonce.data(), counter );

			return crypt_text;
		}

		///	@brief IETF's flavor of the ChaCha20 stream cipher. 96 bits of nonce and 32 bits of counter.
		///
		///	The nonce should not be random. If you need random nonces, use XChaCha20.
		///
		///	@param text The (cipher/plain)text
		///	@param nonce The nonce
		///	@param counter The counter to begin the stream with, if any.
		///	@returns The (cipher/plain)text (de/en)crypted with the ChaCha20 stream.
		[[nodiscard]] ::std::vector<uint8_t> ietf_chacha( const ::std::vector<uint8_t>& text, const ::std::array<uint8_t, 12>& nonce, uint32_t counter = 0 ) const noexcept {
			::std::vector<uint8_t> crypt_text = { text };
			detail::crypto_chacha20_ietf( crypt_text.data(), text.data(), text.size(), _secret_key.data(), nonce.data(), counter );

			return crypt_text;
		}
	};

	///	@brief The poly1305 Carter-Wegman one-time MAC
	///	@warning REUSING KEYS WILL ALLOW AN ATTACKER TO RECOVER THE KEY.
	///	@warning POLY1305 MACS CAN BE TRIVIALLY COLLIDED WITH CHOSEN CIPHERTEXT.
	///
	///	Nonce Reuse - Not Even Once!™
	class poly1305 {
		secret_box<detail::crypto_poly1305_ctx> _context = {};
	public:
		explicit poly1305( ::std::array<uint8_t, 32>&& nonce_key ) noexcept {
			secret_array<uint8_t, 32> key = secret_array( ::std::move( nonce_key ) );
			detail::crypto_poly1305_init( _context, key.data() );
		}

		///	@brief Append a message to the MAC
		[[nodiscard]] poly1305 with_update( const ::std::vector<uint8_t>& message ) const noexcept {
			poly1305 self = poly1305(*this);
			detail::crypto_poly1305_update( self._context, message.data(), message.size() );

			return self;
		}

		///	@brief Get the current MAC
		[[nodiscard]] ::std::array<uint8_t, 16> finalize() const noexcept {
			poly1305 self = poly1305(*this);
			::std::array<uint8_t, 16> mac = {};
			detail::crypto_poly1305_final( self._context, mac.data() );

			return mac;
		}

	public:
		///	@brief One-off MAC of a provided message
		///	@param message the ciphertext to authenticate
		///	@param nonce_key Wiped on return. The secret one-time key.
		static ::std::array<uint8_t, 16> mac( const ::std::vector<uint8_t>& message, ::std::array<uint8_t, 32>&& nonce_key ) noexcept {
			::std::array<uint8_t, 16> mac = {};
			secret_array<uint8_t, 32> key = secret_array( ::std::move( nonce_key ) );

			detail::crypto_poly1305( mac.data(), message.data(), message.size(), key.data() );

			return mac;
		}
	};

	///	@brief Fast hashing & keyed PRF with blake2b
	template<size_t HashSize>
	class blake2b {
		secret_box<detail::crypto_blake2b_ctx> _context = {};
	public:
		static_assert(HashSize <= 64, "HashSize must be between 1 and 64");

		///	@brief Construct a keyed blake2b instance by taking ownership of a secret key.
		///
		///	The array passed into the constructor will be wiped, to prevent copies of the key
		///	from floating around in memory. This object wipes itself on destruction.
		///
		///	@param secret_key Wiped on return. The secret key used for keyed blake2b
		explicit blake2b( ::std::vector<uint8_t>&& secret_key) noexcept {
			secret_vector<uint8_t, 64> key = secret_vector<uint8_t, 64>( ::std::move( secret_key ) );
			detail::crypto_blake2b_keyed_init( _context, HashSize, key.data(), key.size() );
		}

		///	@brief Construct an unkeyed blake2b instance
		blake2b() noexcept {
			detail::crypto_blake2b_init( _context, HashSize );
		}

		///	@brief Append a message to the hash
		[[nodiscard]] blake2b with_update( const ::std::vector<uint8_t>& message ) const noexcept {
			blake2b self = blake2b(*this);
			detail::crypto_blake2b_update( self._context, message.data(), message.size() );

			return self;
		}

		///	@brief Get the current hash
		[[nodiscard]] ::std::array<uint8_t, HashSize> finalize() const noexcept {
			blake2b self = blake2b(*this);
			::std::array<uint8_t, HashSize> hash = {};
			detail::crypto_blake2b_final( self._context, hash.data() );

			return hash;
		}
	public:
		///	@brief One-off hash of a provided message
		///	@param message The message to hash.
		static ::std::array<uint8_t, HashSize> hash( const ::std::vector<uint8_t>& message ) noexcept {
			::std::array<uint8_t, HashSize> hash = {};
			detail::crypto_blake2b( hash.data(), HashSize, message.data(), message.size() );

			return hash;
		}

		///	@brief One-off keyed hash of a provided key and message.
		///
		///	The key array pased into the constructor will be wiped, to prevent copies of the key
		///	from floating around in memory. This function wipes it's own stack on exit.
		///
		///	@param secret_key Wiped on return. The key for the keyed hash
		///	@param message The message to hash
		static ::std::array<uint8_t, HashSize> hash_keyed( ::std::vector<uint8_t>&& secret_key, const ::std::vector<uint8_t>& message ) noexcept {
			::std::array<uint8_t, HashSize> hash = {};
			secret_vector<uint8_t, 64> key = secret_vector<uint8_t, 64>( ::std::move( secret_key ) );

			detail::crypto_blake2b_keyed( hash.data(), HashSize, key.data(), key.size(), message.data(), message.size() );

			return hash;
		}
	};

	///	@brief Hashing with SHA-512
	class sha512 {
		secret_box<detail::crypto_sha512_ctx> _context = {};
	public:

		///	@brief Construct a sha512 instance
		sha512() noexcept {
			detail::crypto_sha512_init( _context );
		}

		///	@brief Append a message to the hash
		///	@param message A message which is copied and appended into the sha512 hash.
		///	@returns A new object containing the new sha512 state after the hash has been appended.
		[[nodiscard]] sha512 with_update( const ::std::vector<uint8_t>& message ) const noexcept {
			sha512 self = sha512(*this);

			detail::crypto_sha512_update( self._context, message.data(), message.size() );

			return self;
		}

		///	@brief Get the current hash
		///	@returns The SHA-512 digest of all updates applied to this object
		[[nodiscard]] ::std::array<uint8_t, 64> finalize() const noexcept {
			sha512 self = sha512(*this);

			::std::array<uint8_t, 64> hash = {};
			detail::crypto_sha512_final( self._context, hash.data() );

			return hash;
		}
	public:
		///	@brief One-off hash of a provided message
		///	@param message A message which is copied and hashed
		///	@returns The SHA-512 digest of the message
		static ::std::array<uint8_t, 64> hash( const ::std::vector<uint8_t>& message ) noexcept {
			::std::array<uint8_t, 64> hash = {};
			detail::crypto_sha512( hash.data(), message.data(), message.size() );

			return hash;
		}

		///	@brief One-off hash of a provided message
		///	@param message A message which is copied and hashed
		///	@returns The SHA-512 digest of the message
		template<size_t MessageLength>
		static ::std::array<uint8_t, 64> hash( const ::std::array<uint8_t, MessageLength>& message ) noexcept {
			::std::array<uint8_t, 64> hash = {};
			detail::crypto_sha512( hash.data(), message.data(), message.size() );

			return hash;
		}
	};

	///	@brief Keyed hashing with HMAC-SHA-512
	class hmacsha512 {
		secret_box<detail::crypto_sha512_hmac_ctx> _context = {};
	public:
		///	@brief Construct an unkeyed HMAC instance (key is 0)
		hmacsha512() noexcept {
			detail::crypto_sha512_hmac_init( _context, nullptr, 0 );
		}

		///	@brief Construct a keyed HMAC instance using the specified key
		///
		///	@param secret_key Wiped on return. The secret key for HMAC
		explicit hmacsha512( ::std::vector<uint8_t>&& secret_key ) noexcept {
			secret_vector<uint8_t> key = secret_vector( std::move(secret_key) );
			detail::crypto_sha512_hmac_init( _context, key.data(), key.size() );
		}

		///	@brief Append a message to the hash
		///	@param message A message which is copied and appended into the hmac hash.
		///	@returns A new object containing the new hmac state after the hash has been appended.
		[[nodiscard]] hmacsha512 with_update( const ::std::vector<uint8_t>& message ) const noexcept {
			hmacsha512 self = hmacsha512(*this);
			detail::crypto_sha512_hmac_update( self._context, message.data(), message.size() );

			return self;
		}

		///	@brief Get the current hash
		///	@returns The HMAC-SHA-512 digest of all updates applied to this object
		[[nodiscard]] ::std::array<uint8_t, 64> finalize() const noexcept {
			hmacsha512 self = hmacsha512(*this);
			::std::array<uint8_t, 64> hash = {};
			detail::crypto_sha512_hmac_final( self._context.object(), hash.data() );

			return hash;
		}
	public:
		///	@brief one-off hash for a provided message.
		///
		///	@param secret_key Wiped on return. The secret used as the HMAC key
		///	@message salt Copied. The public message input into HMAC
		static ::std::array<uint8_t, 64> hmac( ::std::vector<uint8_t>&& secret_key, const ::std::vector<uint8_t>& message ) noexcept {
			::std::array<uint8_t, 64> hash = {};
			secret_vector<uint8_t> key = secret_vector( ::std::move(secret_key) );

			detail::crypto_sha512_hmac( hash.data(), key.data(), key.size(), message.data(), message.size() );

			return hash;
		}

		///	@brief one-off hash for a provided message, where the roles of key and message are reversed.
		///
		///	@param secret_message Wiped on return. The secret message input into HMAC
		///	@param salt Copied. The public salt input as the HMAC key
		static ::std::array<uint8_t, 64> hmac_salt( ::std::vector<uint8_t>&& secret_message, const ::std::vector<uint8_t>& salt ) noexcept {
			::std::array<uint8_t, 64> hash = {};
			secret_vector<uint8_t> key = secret_vector( ::std::move(secret_message) );

			detail::crypto_sha512_hmac( hash.data(), salt.data(), salt.size(), key.data(), key.size() );

			return hash;
		}
	};

	///	@brief HMAC-based Key Derivation Function
	///
	///	HKDF extracts randomness from a non-random string (say, the result of calling x25519.diffie_hellman)
	///	and then offers an interface to use that randomness to generate random keys. You must choose at least
	///	two global constants that never change: SALT and INFO. Salt is a domain separator for your application;
	///	choose a random 128-bit key, for example. INFO is specific to each key you generate; for example,
	///	If you wanted to generate a "sending key" and "receiving key" from one diffie-hellman secret, you'd do:
	///
	/// ```cpp
	///	auto extract = hkdfsha512( ikm, "global constant salt value :^)" )
	///	auto aliceReceivingKey = extract.expand<32>( "alice's receiving key" );
	///	auto aliceSendingKey = extract.expand<32>( "bob's receiving key" );
	/// ```
	class hkdfsha512 {
		secret_array<uint8_t, 64> _prk = {};
		::std::vector<uint8_t> _salt = {};
	public:

		///	@brief Extract randomness from an initial-keying-material string to generate random keys
		///
		///	@param ikm Wiped on return. The initial key material consumed for HKDF.
		///	@param salt The salt for HKDF. This should be a global, public constant.
		explicit hkdfsha512( ::std::vector<uint8_t>&& ikm, const ::std::vector<uint8_t>& salt ) noexcept
			: _salt(salt) {
			_prk = secret_array( hmacsha512::hmac_salt( ::std::move(ikm), _salt ) );
		};

		///	@brief Expand the specified key from the initial keying material
		///	@param info the info string to derive a key for.
		///	@return the info string's N-byte secret key.
		template<size_t Size>
		::std::array<uint8_t, Size> expand( const ::std::vector<uint8_t>& info ) const noexcept {
			std::array<uint8_t, Size> okm = {};

			detail::crypto_sha512_hkdf_expand( okm.data(), okm.size(), _prk.data(), _prk.size(), info.data(), info.size() );

			return okm;
		}
	public:
		template<size_t Size>
		::std::array<uint8_t, Size> hkdf( ::std::vector<uint8_t>&& ikm, const ::std::vector<uint8_t>& salt, const ::std::vector<uint8_t>& info ) noexcept {
			std::array<uint8_t, Size> okm = {};
			secret_vector<uint8_t> key = secret_vector( ::std::move(ikm) );

			detail::crypto_sha512_hkdf( okm.data(), okm.size(), key.data(), key.size(), salt.data(), salt.size(), info.data(), info.size());

			return okm;
		}
	};


	///	@brief Fast diffie-hellman key exchanges over Curve25519
	class x25519 {
		secret_array<uint8_t, 32> _secret_key = {};

	public:
		///	@brief Construct an x25519 instance by taking ownership of a secret key.
		///
		///	The array passed into the constructor will be wiped, to prevent copies of the key
		///	from floating around in memory. This object wipes itself on destruction.
		///
		///	@param secret_key Wiped on return. The secret key.
		explicit x25519( ::std::array<uint8_t, 32>&& secret_key) noexcept
			: _secret_key{ ::std::move( secret_key ) } {
		}

		///	@brief Create a public key from this secret key
		///
		///	Deterministically creates a public key from the x25519 generator using the specified secret key.
		///
		///	@params none
		///	@returns The public key associated with the secret key
		[[nodiscard]] inline ::std::array<uint8_t, 32> public_key() const noexcept {
			::std::array<uint8_t, 32> public_key = {};
			detail::crypto_x25519_public_key( public_key.data(), _secret_key.data() );

			return public_key;
		}

		///	@brief Create a public key from this secret key, but over the whole curve rather than the X25519 group.
		///	@warning LEAKS INFORMATION ABOUT THE SECRET KEY.
		///
		///	Deterministically creates a public key from the x25519 generator, plus a small order subgroup,
		///	from the secret key. This creates more uniform results but will leak information about the secret key.
		///	Use only for ephemeral exchanges where obfuscation is a requirement, and knocking off a few bits of
		///	security isn't that big of a deal.
		///
		///	@params none
		///	@returns The public key associated with the secret key
		[[nodiscard]] inline ::std::array<uint8_t, 32> uniform_public_key() const noexcept {
			::std::array<uint8_t, 32> public_key = {};
			detail::crypto_x25519_dirty_fast( public_key.data() , _secret_key.data() );

			return public_key;
		}

		///	@brief Perform a diffie-hellman key exchange
		///
		///	Deterministically creates a shared secret between your private key and someone else's public
		///	key. Note that this secret is actually a curve on the point, and therefore is not uniformly
		///	distributed; you will need to use a key derivation function to get a viable secret.
		///
		///	@param their_public_key A curve point acting as a public key
		///	@returns The curve point (their_public_key + our_secret_key)
		[[nodiscard]] inline secret_array<uint8_t, 32> diffie_hellman( const ::std::array<uint8_t, 32>& their_public_key ) const noexcept {
			secret_array<uint8_t, 32> curve_point = {};
			detail::crypto_x25519( curve_point.data(), _secret_key.data(), their_public_key.data() );

			return curve_point;
		}

		///	@brief Perform an inverse diffie-hellman key exchange
		///
		///	Deterministically creates a shared secret between your private key and someone else's public
		///	key. Note that this secret is actually a curve on the point, and therefore is not uniformly
		///	distributed; you will need to use a key derivation function to get a viable secret.
		///
		///	This exchange differs from normal diffie-hellman in that we add the modular inverse of our secret
		///	instead of our actual secret. This is practically equivalent to subtraction, so we can perform
		///	g((A + r) + B - r) if we wanted to. Note that if we do this on our own public key, we get the generator.
		///
		///	@param their_public_key A curve point acting as a public key
		///	@returns The curve point (their_public_key - our_secret_key)
		[[nodiscard]] inline secret_array<uint8_t, 32> inverse_diffie_hellman( const ::std::array<uint8_t, 32>& their_public_key ) const noexcept {
			secret_array<uint8_t, 32> curve_point = {};
			detail::crypto_x25519( curve_point.data(), _secret_key.data(), their_public_key.data() );

			return curve_point;
		}
	};

	///	@brief The elligator method for obscuring diffie-hellman exchanges.
	///	@warning Only use for ephemeral keys--Leaks information about the secret key!
	class elligator_x25519 {
		secret_array<uint8_t, 32> _secret_key = {};
		::std::array<uint8_t, 32> _public_key = {};

	public:
		///	@brief Instantiates an elligator_x25519 instance with this private key. Wipes the private key on return.
		///	@param secret_key Wiped on return. The seed used to select a secret key
		explicit elligator_x25519( ::std::array<uint8_t, 32>&& secret_key ) noexcept {
			//	The keygen procedure wipes the seed for us, as well. Thanks, I think?
			detail::crypto_elligator_key_pair(_public_key.data(), _secret_key.data(), secret_key.data());
		}

		///	@brief Get the obscured public key associated with this elligator_x25519 instance
		///	@returns Our public key, but obscured to look like random noise.
		[[nodiscard]] inline ::std::array<uint8_t, 32> hidden_public_key() const noexcept {
			return _public_key;
		}

		///	@brief Get this elligator instance as a pure x25519 instance
		///	@returns An x25519 instance we can use to perform a key exchange
		[[nodiscard]] inline x25519 to_x25519() const noexcept {
			return x25519( ::std::array<uint8_t, 32>(_secret_key) );
		}

	public:
		///	@brief Unhide someone else's hidden public key so that we can do an x25519 exchange with them.
		///	@param their_hidden_public_key Their elligator hidden_public_key value
		///	@returns An x25519 public key for use with diffie_hellman exchanges.
		[[nodiscard]] inline static ::std::array<uint8_t, 32> map( const ::std::array<uint8_t, 32>& their_hidden_public_key ) noexcept {
			::std::array<uint8_t, 32> public_key = {};
			detail::crypto_elligator_map( public_key.data(), their_hidden_public_key.data() );

			return public_key;
		}

		///	@brief Given a montgomery public key, attempt to hide it.
		///	Note that this fails on about half of all public keys. You'll probably need to try multiple. This is already
		///	handled deterministically in the constructor of elligator_x25519(). The inverse of elligator_x25519::map.
		///
		///	@param point the x25519 public key, generated from x25519::uniform_public_key
		///	@param tweak a random 8-bit number.
		///	@returns nullopt on failure, a masked public key on success.
		[[nodiscard]] inline static ::std::optional<::std::array<uint8_t, 32>> inverse_map( const ::std::array<uint8_t, 32>& point, uint8_t tweak ) noexcept {
			::std::array<uint8_t, 32> hidden = {};
			if (detail::crypto_elligator_rev(hidden.data(), point.data(), tweak) != 0) {
				//	returns non-zero on failure.
				return std::nullopt;
			}
			return hidden;
		}
	};

	///	@brief Fast schnorr signatures over Edwards25519
	class ed25519 {
		secret_array<uint8_t, 32> _secret_key_scalar = {};
		secret_array<uint8_t, 64> _secret_key = {};
		::std::array<uint8_t, 32> _public_key = {};
	public:
		///	@brief Instantiates an ed25519 instance with this private key. Wipes the private key on return.
		///	@param secret_key Wiped on return. The secret key.
		explicit ed25519( ::std::array<uint8_t, 32>&& secret_key ) noexcept {
			std::copy_n( sha512::hash( secret_key ).begin(), 32, _secret_key_scalar.begin() );
			//	The keygen procedure wipes the private key for us. Thanks, I think?
			detail::crypto_ed25519_key_pair(_secret_key.data(), _public_key.data(), secret_key.data());
		}

		///	@brief Every edwards public key maps to exactly one curve25519 public key.
		///
		///	@warning This is not true in reverse; one Curve25519 point maps to two edwards25519 points.
		///	@warning This is handled by monocypher by forcing the sign bit to be positive.
		[[nodiscard]] inline x25519 to_x25519() const noexcept {
			return x25519( secret_array(_secret_key_scalar) );
		}

		///	@brief Get the public key associated with this ed25519 instance
		///	@returns Our public key
		[[nodiscard]] inline ::std::array<uint8_t, 32> public_key() const noexcept {
			return _public_key;
		}

		///	@brief Sign the message with the private key.
		///	@param message The message to sign
		///	@returns Our signature of the message
		[[nodiscard]] inline ::std::array<uint8_t, 64> sign( const ::std::vector<uint8_t>&  message ) const noexcept {
			::std::array<uint8_t, 64> signature = {};
			detail::crypto_ed25519_sign( signature.data(), _secret_key.data(), message.data(),  message.size() );

			return signature;
		}

		///	@brief Sign the hashed message with the private key
		///	@param message the sha512 instance containing the signed message
		///	@returns Our signature of the message
		[[nodiscard]] inline ::std::array<uint8_t, 64> sign_prehashed( const sha512& message ) const noexcept {
			::std::array<uint8_t, 64> signature = {};
			::std::array<uint8_t, 64> hash = message.finalize();
			detail::crypto_ed25519_ph_sign( signature.data(), _secret_key.data(), hash.data() );

			return signature;
		}
	public:
		///	@brief Verify that the (signature, message) pair is valid for this public key.
		///	@warning This is not constant time, do not use on secret inputs.
		///	@param public_key The public key of the signer
		///	@param signature The alleged signature of this message
		///	@param message The message allegedly signed by the signer
		///	@returns True if the alleged signature is valid. False otherwise.
		[[nodiscard]] static bool verify( const ::std::array<uint8_t, 32>& public_key, const ::std::array<uint8_t, 64>& signature,
			const ::std::vector<uint8_t>&  message ) noexcept {
			if (detail::crypto_ed25519_check( signature.data(), public_key.data(), message.data(), message.size() ) == 0) {
				//	returns 0 on valid signature
				return true;
			}
			return false;
		}
		///	@brief Verify that the (signature, message) pair is valid for this public key.
		///	@warning This is not constant time, do not use on secret inputs.
		///	@param public_key The public key of the signer
		///	@param signature The alleged signature of this message
		///	@param message The sha512 hash of the message allegedly signed by the signer
		///	@returns True if the alleged signature is valid. False otherwise.
		[[nodiscard]] static bool verify_prehashed( const ::std::array<uint8_t, 32>& public_key, const ::std::array<uint8_t, 64>& signature,
			const sha512& message ) noexcept {
			::std::array<uint8_t, 64> hash = message.finalize();

			if (detail::crypto_ed25519_ph_check( signature.data(), public_key.data(), hash.data() ) == 0) {
				//	returns 0 on valid signature
				return true;
			}
			return false;
		}

		///	@brief Converts an Ed25519 public key to an x25519 public key
		///	@warning Two Ed25519 public keys will both map to the same x25519 public key.
		///
		///	@param their_edwards_public_key An edwards public key
		///	@returns The montgomery (x25519) public key associated with the edwards public key.
		[[nodiscard]] static ::std::array<uint8_t, 32> to_x25519( const ::std::array<uint8_t, 32>& their_edwards_public_key ) {
			::std::array<uint8_t, 32> their_montgomery_public_key = {};
			detail::crypto_eddsa_to_x25519( their_montgomery_public_key.data(), their_edwards_public_key.data() );

			return their_montgomery_public_key;
		}
	};

	enum Argon2Type {
		///	Argon2 with deterministic memory access.
		///	"Easier" to crack with an ASIC, but doesn't leak as much to side channels.
		///	(Easier is subjective--don't overthink it.)
		argon2i = CRYPTO_ARGON2_I,

		///	Argon2 with a mix of deterministic and independent memory access.
		///	Leaks much less information through side channels than argon2d, while
		///	inheriting some of the ASIC-resisting properties.
		argon2id = CRYPTO_ARGON2_ID,

		///	Argon2 with key-dependent memory access.
		///	Much more difficult to crack with an ASIC, but also leaks information
		///	through timing side-channels.
		argon2d = CRYPTO_ARGON2_D,
	};

	///	@brief The Argon2 password-based key derivation function / key stretching algorithm
	///
	///	Argon2 takes a credential of low entropy, a salt of high entropy, and some optional associated
	///	data, and "stretches" the key so that the difficulty of brute forcing the underlying entropy is
	///	much harder than it would be otherwise.
	///
	///	The low-memory parameter recommendation is usually on the order of 64 megabytes of memory
	///	(m = Memory = 65535) and at least 3 passes (t = Passes = 3). It is not recommended to use multiple
	///	lanes (p = Parallelism = 1) for this implementation as it is not multithreaded.
	///
	///	@param credential Wiped on return. The credential to hash
	///	@param salt Copied. A randomly generated salt, used as domain separation
	///	@param key Wiped on return. An optional secret key.
	///	@param ad Copied. Optional associated data to be authenticated alongside the credential.
	template<Argon2Type Type, size_t Memory, size_t Passes, size_t HashSize = 16, size_t Parallelism = 1>
	::std::array<uint8_t, HashSize> argon2(
		::std::vector<uint8_t>&& credential, const ::std::vector<uint8_t>& salt,
		::std::vector<uint8_t>&& key = {}, const ::std::vector<uint8_t>& ad = {}
	) {
		static_assert(Passes >= 2, "It is VERY STRONGLY recommended to use more than one pass.");

		secret_vector<uint8_t> password = secret_vector( std::move(credential) );
		secret_vector<uint8_t> secret_key = secret_vector( std::move(key) );

		auto *work_area = new secret_array<uint64_t, (Memory * 1024 / 8) + 1>;
		::std::array<uint8_t, HashSize> hash = {};

		detail::crypto_argon2_config config = {};
		config.algorithm = Type;
		config.nb_blocks = Memory;
		config.nb_passes = Passes;
		config.nb_lanes = Parallelism;

		detail::crypto_argon2_inputs inputs = {};
		inputs.pass = password.data();
		inputs.salt = salt.data();
		inputs.pass_size = static_cast<uint32_t>(password.size());
		inputs.salt_size = static_cast<uint32_t>(salt.size());

		detail::crypto_argon2_extras extras = {};
		extras.key = secret_key.data();
		extras.ad = ad.data();
		extras.key_size = static_cast<uint32_t>(secret_key.size());
		extras.ad_size = static_cast<uint32_t>(ad.size());

		detail::crypto_argon2( hash.data(), hash.size(), work_area, config, inputs, extras );

		delete work_area;
		return hash;
	}


	namespace hazmat {

		inline std::array<uint8_t, 32> x25519_to_ed25519( const std::array<uint8_t, 32>& their_montgomery_public_key ) {
			std::array<uint8_t, 32> edwards = {};
			detail::crypto_x25519_to_eddsa( edwards.data(), their_montgomery_public_key.data() );

			return edwards;
		}

		inline std::array<uint8_t, 32> ed25519_trim_scalar( const std::array<uint8_t, 32>& uniform_scalar ) {
			std::array<uint8_t, 32> edwards_scalar = {};
			detail::crypto_eddsa_trim_scalar( edwards_scalar.data(), uniform_scalar.data() );

			return edwards_scalar;
		}

		inline std::array<uint8_t, 32> ed25519_mul_add( const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b, const std::array<uint8_t, 32>& c ) {
			std::array<uint8_t, 32> r = {};
			detail::crypto_eddsa_mul_add( r.data(), a.data(), b.data(), c.data() );

			return r;
		}

		inline std::array<uint8_t, 32> ed25519_reduce( const std::array<uint8_t, 64>& expanded ) {
			std::array<uint8_t, 32> reduced = {};
			detail::crypto_eddsa_reduce( reduced.data(), expanded.data() );

			return reduced;
		}

		inline std::array<uint8_t, 32> ed25519_scalarbase( const std::array<uint8_t, 32>& scalar ) {
			std::array<uint8_t, 32> point = {};
			detail::crypto_eddsa_scalarbase( point.data(), scalar.data() );

			return point;
		}

		inline bool ed25519_check_equation( const std::array<uint8_t, 64>& signature, const std::array<uint8_t, 32>& pk, const std::array<uint8_t, 64>& h ) {
			return detail::crypto_eddsa_check_equation( signature.data(), pk.data(), h.data() ) == 0;
		}

	}

#ifdef MONOCYPHER_CPP_NAMESPACE_PLEASE_CLOSE_KTHX
}
#endif

#endif	//	MONOCYPHER_HPP