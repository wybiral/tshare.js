/**
 * This module implements methods for (2,3) threshold secret sharing for
 * splitting secrets into three shares. None of the shares alone give away any
 * information about the secret (other than the length) but any combination of
 * two shares is able to fully recover the secret.
 */

(exports => {
'use strict';

/**
 * Splits m into 3 shares using (2,3) threshold secret sharing algorithm.
 * defined by:
 *  m = secret byte with bits [m7 m6 m5 m4 m3 m2 m1 m0]
 *  r = random byte
 *  s0 = [ 0  0  0  0 m7 m6 m5 m4] ^ r
 *  s1 = [m3 m2 m1 m0  0  0  0  0] ^ r
 *  s2 = [m7 m6 m5 m4 m3 m2 m1 m0] ^ r
 * The first byte of each share is a tag denoting which share it is.
 * @param {Uint8Array} m - Byte array secret to split.
 * @return {Array.<Uint8array>} - Array of tagged share byte arrays.
*/
function splitBytes(m) {
    if (!(m instanceof Uint8Array)) {
        throw 'm must be Uint8Array';
    }
    const n = m.length;
    const r = randomBytes(n);
    const s0 = new Uint8Array(n + 1);
    s0[0] = 0x00;
    const s1 = new Uint8Array(n + 1);
    s1[0] = 0x01;
    const s2 = new Uint8Array(n + 1);
    s2[0] = 0x02;
    for (let i = 0; i < n; i++) {
        const x = m[i];
        const y = r[i];
        const j = i + 1;
        s0[j] = ((x & 0xf0) >> 4) ^ y;
        s1[j] = ((x & 0x0f) << 4) ^ y;
        s2[j] = x ^ y;
    }
    return [s0, s1, s2];
}

/**
 * Recovers secret from any two tagged shares.
 * @param {Uint8Array} a - Byte array of tagged share.
 * @param {Uint8Array} b - Byte array of tagged share.
 * @return {Uint8array} - Byte array of reconstructed secret.
 */
function joinBytes(a, b) {
    if (!(a instanceof Uint8Array)) {
        throw 'a must be Uint8Array';
    }
    if (!(b instanceof Uint8Array)) {
        throw 'b must be Uint8Array';
    }
    if (a.length != b.length) {
        throw 'size mismatch';
    }
    if (a.length < 1) {
        throw 'invalid shares';
    }
    if (a[0] > b[0]) {
        [a, b] = [b, a];
    }
    const m = new Uint8Array(a.length - 1);
    if (a[0] === 0x00 && b[0] === 0x01) {
        joinBytes01(m, a, b);
    } else if (a[0] === 0x00 && b[0] === 0x02) {
        joinBytes02(m, a, b);
    } else if (a[0] === 0x01 && b[0] === 0x02) {
        joinBytes12(m, a, b);
    } else {
        throw 'invalid shares';
    }
    return m;
}

/**
 * when a = s0 and b = s1
 *  c = a ^ b
 *  m = [c3 c2 c1 c0 0 0 0 0] | [0 0 0 0 c7 c6 c5 c4]
 */
function joinBytes01(m, a, b) {
    for (let i = 0; i < m.length; i++) {
        const c = a[i + 1] ^ b[i + 1];
        m[i] = ((c << 4) & 0xf0) | ((c >> 4) & 0x0f);
    }
}

/**
 * when a = s0 and b = s2
 *  c = a ^ b
 *  m = [0 0 0 0 c7 c6 c5 c4] ^ c
 */
function joinBytes02(m, a, b) {
    for (let i = 0; i < m.length; i++) {
        const c = a[i + 1] ^ b[i + 1];
        m[i] = ((c & 0xf0) >> 4) ^ c;
    }
}

/**
 * when a = s1 and b = s2
 *  c = a ^ b
 *  m = [c3 c2 c1 c0 0 0 0 0] ^ c
 */
function joinBytes12(m, a, b) {
    for (let i = 0; i < m.length; i++) {
        const c = a[i + 1] ^ b[i + 1];
        m[i] = ((c & 0x0f) << 4) ^ c;
    }
}

/**
 * Wrapper around crypto.randomBytes or crypto.getRandomValues for cross-
 * platform support.
 */
function randomBytes(n) {
    if (typeof window === 'undefined') {
        const b = require('crypto').randomBytes(n);
        return new Uint8Array(b);
    }
    const a = new Uint8Array(n);
    window.crypto.getRandomValues(a);
    return a;
}

exports.splitBytes = splitBytes;
exports.joinBytes = joinBytes;

})(typeof exports === 'undefined' ? this.tshare = {} : exports);
