/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Helper functions common to many unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var MslTestUtils;
var MslTestUtils$Algorithm;

(function() {
	/** Base service token name. */
    var SERVICE_TOKEN_NAME = "serviceTokenName";
    /**
     * Maximum number of service tokens to randomly generate. This needs to be
     * large enough to statistically create the applicable set of service
     * tokens for the tests.
     */
    var NUM_SERVICE_TOKENS = 12;
    
    /** Wrapping key derivation algorithm salt. */
    var SALT = base64$decode("AnYXmE9iJ1OaYwuJfAF9aQ==");
    /** Wrapping key derivation algorithm info. */
    var INFO = base64$decode("gJ+Cp63fVI0+qd0Gf/m7kQ==");
    /** Wrapping key length in bytes. */
    var WRAPPING_KEY_LENGTH = 128 / 8;

    MslTestUtils = {
        /**
         * Returns an RSA key pair with the specified Web Crypto algorithm
         * and key length.
         * 
         * @param {WebCryptoAlgorithm} algo Web Crypto algorithm.
         * @param {WebCryptoUsage} usages Web Crypto key usages.
         * @param {number} length key length in bits.
         * @param {result: function(PublicKey, PrivateKey), error: function(Error)}
         *        callback the callback that will receive the RSA key pair or
         *        any thrown exceptions.
         */
        generateRsaKeys: function (algo, usages, length, callback) {
            AsyncExecutor(callback, function() {
                var oncomplete = function(result) {
                    PrivateKey$create(result.privateKey, {
                        result: function(privateKey) {
                            PublicKey$create(result.publicKey, {
                                result: function(publicKey) {
                                    callback.result(publicKey, privateKey);
                                },
                                error: function(e) {
                                    callback.error(e);
                                }
                            });
                        },
                        error: function(e) {
                            callback.error(e);
                        }
                    });
                };
                var onerror = function(e) {
                    callback.error(new Error("error creating RSA keys"));
                };
                mslCrypto["generateKey"]({ 'name': algo['name'], 'hash': algo['hash'], 'modulusLength': length, 'publicExponent': new Uint8Array([0x01, 0x00, 0x01]), }, false, usages)
                    .then(oncomplete, onerror);

            });
        },
        
        /**
         * Returns a Diffie-Hellman key pair generated using the provided
         * parameter specification.
         * 
         * @param {DHParameterSpec} params Diffie-Hellman parameters
         *        specification.
         * @param {result: function(PublicKey, PrivateKey), error: function(Error)}
         *        callback the callback that will receive the Diffie-Hellman key
         *        pair or any thrown exceptions.
         */
        generateDiffieHellmanKeys: function (params, callback) {
            AsyncExecutor(callback, function() {
                var oncomplete = function(keyPair) {
                    callback.result(keyPair.publicKey, keyPair.privateKey);
                };
                var onerror = function(e) {
                    callback.error(new Error("error creating Diffie-Hellman keys"));
                };
                mslCrypto['generateKey']({
                    'name': WebCryptoAlgorithm.DIFFIE_HELLMAN,
                    'prime': params.p,
                    'generator': params.g
                }, true, WebCryptoUsage.DERIVE_KEY).then(oncomplete, onerror);
            });
        },
        
	    /**
	     * Returns a master token with the identity of the MSL context entity
	     * authentication data that is not renewable or expired.
	     * 
	     * @param {MslContext} ctx MSL context.
	     * @param {number} sequenceNumber master token sequence number to use.
	     * @param {number} serialNumber master token serial number to use.
		 * @param {result: function(MasterToken), error: function(Error)}
		 *        callback the callback functions that will receive the new
		 *        master token or any thrown exceptions.
	     * @throws MslEncodingException if there is an error encoding the JSON
	     *         data.
	     * @throws MslCryptoException if there is an error encrypting or signing
	     *         the token data.
	     */
	    getMasterToken: function (ctx, sequenceNumber, serialNumber, callback) {
	    	AsyncExecutor(callback, function() {
		        var renewalWindow = new Date(Date.now() + 10000);
		        var expiration = new Date(Date.now() + 20000);
		        ctx.getEntityAuthenticationData(null, {
		        	result: function(entityAuthData) {
		        		var identity = entityAuthData.identity;
				        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
				        var hmacKey = MockPresharedAuthenticationFactory.KPH;
				        MasterToken$create(ctx, renewalWindow, expiration, sequenceNumber, serialNumber, null, identity, encryptionKey, hmacKey, callback);		        		
		        	},
		        	error: function(err) { callback.error(err); }
		        });
	    	});
	    },
	    
	    /**
	     * Returns an untrusted master token with the identity of
	     * {@link MockPresharedAuthenticationFactory#PSK_ESN} that is not
	     * renewable or expired.
	     * 
	     * @param {MslContext} ctx MSL context.
		 * @param {result: function(MasterToken), error: function(Error)}
		 *        callback the callback functions that will receive the new
		 *        untrusted master token or any thrown exceptions.
	     * @throws MslEncodingException if there is an error encoding the JSON
	     *         data.
	     * @throws MslCryptoException if there is an error encrypting or signing
	     *         the token data.
	     * @throws MslException if the master token is constructed incorrectly.
	     * @throws JSONException if there is an error editing the JSON data.
	     */
	    getUntrustedMasterToken: function (ctx, callback) {
	    	AsyncExecutor(callback, function() {
		        var renewalWindow = new Date(Date.now() + 10000);
		        var expiration = new Date(Date.now() + 20000);
		        ctx.getEntityAuthenticationData(null, {
		        	result: function(entityAuthData) {
			        	var identity = entityAuthData.identity;
				        var encryptionKey = MockPresharedAuthenticationFactory.KPE;
				        var hmacKey = MockPresharedAuthenticationFactory.KPH;
				        MasterToken$create(ctx, renewalWindow, expiration, 1, 1, null, identity, encryptionKey, hmacKey, {
				        	result: function(masterToken) {
				        		AsyncExecutor(callback, function() {
					        		var json = JSON.stringify(masterToken);
					    	        var jo = JSON.parse(json);
					    	        var signature = base64$decode(jo["signature"]);
					    	        ++signature[1];
					    	        jo["signature"] = base64$encode(signature);
					    	        MasterToken$parse(ctx, jo, callback);
				        		});
				        	},
				        	error: function(err) { callback.error(err); }
				        });
		        	},
		        	error: function(err) { callback.error(err); }
		        });
	    	});
	    },
	    
	    /**
	     * Returns a user ID token with the identity of the provided user that is
	     * not renewable or expired.
	     * 
	     * @param {MslContext} ctx MSL context.
	     * @param {MasterToken} masterToken master token to bind against.
	     * @param {number} serialNumber user ID token serial number to use.
	     * @param {MslUser} user MSL user to use.
	     * @param {result: function(UserIdToken), error: function(Error)}
	     *        callback the callback functions that will receive the new
	     *        user ID token or any thrown exceptions.
	     * @throws MslEncodingException if there is an error encoding the JSON
	     *         data.
	     * @throws MslCryptoException if there is an error encrypting or signing
	     *         the token data.
	     */
	    getUserIdToken: function getUserIdToken(ctx, masterToken, serialNumber, user, callback) {
	    	AsyncExecutor(callback, function() {
		        var renewalWindow = new Date(Date.now() + 10000);
		        var expiration = new Date(Date.now() + 20000);
		        UserIdToken$create(ctx, renewalWindow, expiration, masterToken, serialNumber, null, user, callback);
	    	});
	    },
	    
	    /**
	     * Returns an untrusted user ID token with the identity of the provided
	     * user that is not renewable or expired.
	     * 
	     * @param {MslContext} ctx MSL context.
	     * @param {MasterToken} masterToken master token to bind against.
	     * @param {number} serialNumber user ID token serial number to use.
	     * @param {MslUser} user MSL user to use.
         * @param {result: function(UserIdToken), error: function(Error)}
         *        callback the callback functions that will receive the new
         *        user ID token or any thrown exceptions.
	     * @throws MslEncodingException if there is an error encoding the JSON
	     *         data.
	     * @throws MslCryptoException if there is an error encrypting or signing
	     *         the token data.
	     * @throws JSONException if there is an error editing the JSON data.
	     * @throws MslException if the user ID token serial number is out of range.
	     */
	    getUntrustedUserIdToken: function getUntrustedUserIdToken(ctx, masterToken, serialNumber, user, callback) {
	        AsyncExecutor(callback, function() {
                var renewalWindow = new Date(Date.now() + 10000);
                var expiration = new Date(Date.now() + 20000);
                UserIdToken$create(ctx, renewalWindow, expiration, masterToken, serialNumber, null, user, {
                    result: function(userIdToken) {
                        AsyncExecutor(callback, function() {
                            var json = JSON.stringify(userIdToken);
                            var jo = JSON.parse(json);
                            var signature = base64$decode(jo["signature"]);
                            ++signature[1];
                            jo["signature"] = base64$encode(signature);
                            UserIdToken$parse(ctx, jo, masterToken, callback);
                        });
                    },
                    error: callback.error,
                });
	        });
	    },
	    
	    /**
	     * @param {MslContext} ctx MSL context.
	     * @param {MasterToken} masterToken master token to bind against. May be null.
	     * @param {UserIdToken} userIdToken user ID token to bind against. May be null.
	     * @param {result: function(Array.<ServiceToken>), error: function(Error)}
	     *        callback the callback functions that will receive the set of
	     *        new service tokens with random token bindings or any thrown
	     *        exceptions.
	     * @throws MslEncodingException if there is an error encoding the JSON
	     *         data.
	     * @throws MslCryptoException if there is an error encrypting or signing
	     *         the token data.
	     * @throws MslException if there is an error compressing the data.
	     */
	    getServiceTokens: function getServiceTokens(ctx, masterToken, userIdToken, callback) {
	        var random = new Random();
	        var cryptoContext = new NullCryptoContext();
	        var serviceTokens = {};
	        var count = Math.max(NUM_SERVICE_TOKENS, 3);
	        
	        function addToken() {
	        	if (count <= 0) {
	        		var tokens = new Array();
	    	        for (var key in serviceTokens)
	    	        	tokens.push(serviceTokens[key]);
	    	        callback.result(tokens);
	        		return;
	        	}
	        	
	            var name = SERVICE_TOKEN_NAME + random.nextInt();
	            var data = new Uint8Array(32);
	            random.nextBytes(data);
	            var mt = null, uit = null;
	            
	            // Make sure one of each type of token is included.
	            // Otherwise pick a random type.
	            var type = (count < 3) ? count : random.nextInt(3);
	            switch (type) {
	            	case 2:
	            		uit = userIdToken;
	            	case 1:
	            		mt = masterToken;
	            	case 0:
	            		break;
	            }
	            ServiceToken$create(ctx, name, data, mt, uit, false, null, cryptoContext, {
	            	result: function(token) {
	            		serviceTokens[token.uniqueKey()] = token;
	            		--count;
	            		addToken();
	            	},
	            	error: function(err) { callback.error(err); }
	            });
	        }
	        addToken();
	    },
	    
	    /**
         * @param {MslContext} ctx MSL context.
	     * @param {MasterToken} masterToken the master token to bind against.
	     * @param {result: function(Array.<ServiceToken>), error: function(Error)}
	     *        callback the callback functions that will receive the set of
	     *        new random master bound service tokens or any thrown
	     *        exceptions.
	     * @throws MslEncodingException if there is an error constructing the
	     *         service token.
	     * @throws MslCryptoException if there is an error constructing the service
	     *         token.
         * @throws MslException if there is an error compressing the data.
	     */
	    getMasterBoundServiceTokens: function getMasterBoundServiceTokens(ctx, masterToken, callback) {
	        var random = new Random();
	        var cryptoContext = new NullCryptoContext();
	        var tokens = new Array();
	        var count = 1 + random.nextInt(NUM_SERVICE_TOKENS);
	        
	    	function addToken() {
	    		if (count <= 0) {
	    			callback.result(tokens);
	    			return;
	    		}
	    		
	    		var data = new Uint8Array(8);
	            random.nextBytes(data);
	            ServiceToken$create(ctx, "masterbound" + count, data, masterToken, null, false, null, cryptoContext, {
	            	result: function(token) {
	            		tokens.push(token);
	            		--count;
	            		addToken();
	            	},
	            	error: function(err) { callback.error(err); }
	            });
	    	}
	    	addToken();
	    },
	    
	    /**
         * @param {MslContext} ctx MSL context.
	     * @param {MasterToken} masterToken the master token to bind against.
	     * @param {UserIdToken} userIdToken the user ID token to bind against.
	     * @param {result: function(Array.<ServiceToken>), error: function(Error)}
	     *        callback the callback functions that will receive the set of
	     *        new random user ID token bound service tokens or any thrown
	     *        exceptions.
	     * @throws MslEncodingException if there is an error constructing the
	     *         service token.
	     * @throws MslCryptoException if there is an error constructing the service
	     *         token.
         * @throws MslException if there is an error compressing the data.
	     */
	    getUserBoundServiceTokens: function getUserBoundServiceTokens(ctx, masterToken, userIdToken, callback) {
	        var random = new Random();
	        var cryptoContext = new NullCryptoContext();
	        var tokens = new Array();
	        var count = 1 + random.nextInt(NUM_SERVICE_TOKENS);
	        
	    	function addToken() {
	    		if (count <= 0) {
	    			callback.result(tokens);
	    			return;
	    		}
	    		
	    		var data = new Uint8Array(8);
	            random.nextBytes(data);
	            ServiceToken$create(ctx, "userbound" + count, data, masterToken, userIdToken, false, null, cryptoContext, {
	            	result: function(token) {
	            		tokens.push(token);
	            		--count;
	            		addToken();
	            	},
	            	error: function(err) { callback.error(err); }
	            });
	    	}
	    	addToken();
	    },
	    
	    /**
	     * Derives the pre-shared or model group keys AES-128 Key Wrap key from the
	     * provided AES-128 encryption key and HMAC-SHA256 key.
	     * 
	     * @param {string|Uint8Array} encryptionKey Base64-encoded or raw encryption key.
	     * @param {string|Uint8Array} hmacKey Base64-encoded or raw HMAC key.
	     * @return {{result: function(Uint8Array), error: function(Error)}
	     *         callback the callback functions that will receive the
	     *         wrapping key or any thrown exceptions.
	     * @throws CryptoException if there is an error generating the wrapping
	     *         key.
	     */
	    deriveWrappingKey: function deriveWrappingKey(encryptionKey, hmacKey, callback) {
            // Concatenate the keys.
	        AsyncExecutor(callback, function() {
	            var ke, kh;
	            try {
	                ke = (typeof encryptionKey == 'string') ? base64$decode(encryptionKey) : encryptionKey;
	            } catch (e) {
	                throw new MslCryptoException(MslError.INVALID_ENCRYPTION_KEY, "encryptionKey " + encryptionKey, e);
	            }
	            try {
	                kh = (typeof hmacKey == 'string') ? base64$decode(hmacKey) : hmacKey;
	            } catch (e) {
	                throw new MslCryptoException(MslError.INVALID_HMAC_KEY, "hmacKey " + hmacKey, e);
	            }
	            
	            var bits = new Uint8Array(ke.length + kh.length);
	            bits.set(ke, 0);
	            bits.set(kh, ke.length);
	            saltStep(bits);
	        });
	        
	        // HMAC-SHA256 the keys with the salt as the HMAC key.
	        function saltStep(bits) {
                CipherKey$import(SALT, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
                    result: function(saltKey) {
                        var oncomplete = function(result) {
                            infoStep(new Uint8Array(result));
                        };
                        var onerror = function(e) {
                            callback.error(new MslCryptoException(MslError.HMAC_ERROR));
                        };
                        mslCrypto['sign'](WebCryptoAlgorithm.HMAC_SHA256, saltKey.rawKey, bits)
                            .then(oncomplete, onerror);
                    },
                    error: callback.error
                });
	        }
            
	        // HMAC-SHA256 the info with the intermediate key as the HMAC key.
	        function infoStep(intermediateBits) {
	            CipherKey$import(intermediateBits, WebCryptoAlgorithm.HMAC_SHA256, WebCryptoUsage.SIGN_VERIFY, {
	                result: function(intermediateKey) {
	                    AsyncExecutor(callback, function() {
                            var oncomplete = function(result) {
    	                        trunc(new Uint8Array(result));
    	                    };
                            var onerror = function(e) {
    	                        callback.error(new MslCryptoException(MslError.HMAC_ERROR));
    	                    };
                            mslCrypto['sign'](WebCryptoAlgorithm.HMAC_SHA256, intermediateKey.rawKey, INFO)
                                .then(oncomplete, onerror);
	                    });
	                },
	                error: callback.error
	            });
	        }

	        // Grab the first 128 bits.
	        function trunc(finalBits) {
	            AsyncExecutor(callback, function() {
	                return new Uint8Array(finalBits.subarray(0, WRAPPING_KEY_LENGTH));
	            });
	        }
	    },
    };

    MslTestUtils$Algorithm = {
    	/**
    	 * Returns true if two algorithms are equal.
    	 *
    	 * @param {WebCryptoAlgorithm} a the first algorithm.
    	 * @param {WebCryptoAlgorithm} b the second algorithm.
    	 * @return true if the algorithms are equal.
    	 */
    	equals: function equals(a, b) {
    		// IE 11 uses lowercase algorithm names, contrary to spec.
    		if (a['name'].toLowerCase() != b['name'].toLowerCase())
    			return false;
    		if ((a['hash'] && !b['hash']) || (!a['hash'] && b['hash']))
    			return false;
    		if (a['hash'] && a['hash']['name'].toLowerCase() != b['hash']['name'].toLowerCase())
    			return false;
    		return true;
    	},
    };
})();
