/*
this file imported from https://github.com/tj/node-cookie-signature
*/
import { timingSafeEqual } from 'https://deno.land/std@0.123.0/node/_crypto/timingSafeEqual.ts'
import { Buffer } from 'https://deno.land/std@0.123.0/node/buffer.ts'
import { hmac } from "https://deno.land/x/hmac@v2.0.1/mod.ts"
const encoder = new TextEncoder()
/**
 * Sign the given `val` with `secret`.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String}
 * @api private
 */

export const sign = function(val: string, secret: string){
  if ('string' != typeof val) throw new TypeError("Cookie value must be provided as a string.");
    if ('string' != typeof secret) throw new TypeError("Secret string must be provided.");
  return val + '.' + (<string>hmac("sha256", secret , val , "utf8", "base64")).replace(/\=+$/, '');
};

/**
 * Unsign and decode the given `val` with `secret`,
 * returning `false` if the signature is invalid.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String|Boolean}
 * @api private
 */

export const unsign = function(val: string, secret: string): string | boolean {
  if ('string' != typeof val) throw new TypeError("Signed cookie string must be provided.");
  if ('string' != typeof secret) throw new TypeError("Secret string must be provided.");
  var str = val.slice(0, val.lastIndexOf('.'))
    , mac = sign(str, secret)
    , macBuffer = Buffer.from(mac)
    , valBuffer = Buffer.alloc(macBuffer.length);

    valBuffer.write(val);

  return timingSafeEqual(macBuffer, valBuffer) ? str : false;
};