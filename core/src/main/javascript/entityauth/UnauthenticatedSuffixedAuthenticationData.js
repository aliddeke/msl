/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
 * <p>Unauthenticated suffixed entity authentication data. This form of
 * authentication is used by entities that cannot provide any form of entity
 * authentication, and wish to share a root identity across themselves. This
 * scheme may also be useful in cases where multiple MSL stacks need to execute
 * independently on a single entity.</p>
 * 
 * <p>A suffixed scheme can expose an entity to cloning attacks of the root
 * identity as the master token sequence number will now be tied to the
 * root and suffix pair. This is probably acceptable for unauthenticated
 * entities anyway as they have no credentials to provide as proof of their
 * claimed identity.</p>
 * 
 * <p>Unauthenticated suffixed entity authentication data is represented as
 * {@code
 * unauthenticatedauthdata = {
 *   "#mandatory" : [ "root", "suffix" ],
 *   "root" : "string",
 *   "suffix" : "string"
 * }} where:
 * <ul>
 * <li>{@code root} is the entity identity root</li>
 * <li>{@code suffix} is the entity identity suffix</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
var UnauthenticatedSuffixedAuthenticationData;
var UnauthenticatedSuffixedAuthenticationData$parse;

(function() {
    "use strict";
    
    /**
     * JSON key entity root.
     * @const
     * @type {string}
     */
    var KEY_ROOT = "root";
    /**
     * JSON key entity suffix.
     * @const
     * @type {string}
     */
    var KEY_SUFFIX = "suffix";
    
    /**
     * Identity concatenation character.
     * @const
     * @type {string}
     */
    var CONCAT_CHAR = ".";
    
    UnauthenticatedSuffixedAuthenticationData = EntityAuthenticationData.extend({
        /**
         * Construct a new unauthenticated suffixed entity authentication data
         * instance from the specified entity identity root and suffix.
         * 
         * @param {string} root the entity identity root.
         * @param {string} suffix the entity identity suffix.
         */
        init: function init(root, suffix) {
            init.base.call(this, EntityAuthenticationScheme.NONE_SUFFIXED);
            
            // The properties.
            var props = {
                root: { value: root, writable: false, configurable: false },
                suffix: { value: suffix, writable: false, configurable: false },
            };
            Object.defineProperties(this, props);
        },
        
        /**
         * <p>Returns the entity identity. This is equal to the root and suffix
         * strings joined with a period, e.g. {@code root.suffix}.</p>
         * 
         * @return the entity identity.
         */
        getIdentity: function getIdentity() {
            return this.root + CONCAT_CHAR + this.suffix;
        },

        /** @inheritDoc */
        getAuthData: function getAuthData() {
            var result = {};
            result[KEY_ROOT] = this.root;
            result[KEY_SUFFIX] = this.suffix;
            return result;
        },

        /** @inheritDoc */
        equals: function equals(that) {
            if (this === that) return true;
            if (!(that instanceof UnauthenticatedSuffixedAuthenticationData)) return false;
            return (equals.base.call(this, that) && this.root == that.root && this.suffix == that.suffix);
        },
    });
    
    /**
     * Construct a new unauthenticated suffixed entity authentication data
     * instance from the provided JSON object.
     * 
     * @param {object} unauthSuffixedAuthJO the authentication data JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON
     *         representation.
     */
    UnauthenticatedSuffixedAuthenticationData$parse = function UnauthenticatedSuffixedAuthenticationData$parse(unauthSuffixedAuthJO) {
        var root = unauthSuffixedAuthJO[KEY_ROOT];
        var suffix = unauthSuffixedAuthJO[KEY_SUFFIX];
        if (typeof root !== 'string' || typeof suffix !== 'string')
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "Unauthenticated suffixed authdata" + JSON.stringify(unauthSuffixedAuthJO));
        return new UnauthenticatedSuffixedAuthenticationData(root, suffix);
    };
})();
