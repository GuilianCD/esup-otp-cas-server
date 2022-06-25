const crypto = require('crypto');

const conf = require('../conf')


/** @param {number} date */
const seconds_since = (date) => (Date.now() - date) / 1000

function raw_hash(algo, data) {
    const hash = crypto.createHash(algo);
    hash.update(data)
    return hash.digest('hex')
}

/** @param {String} uid */
function get_hash(uid) {
    const d = new Date();
    const present_salt = d.getUTCDate()+d.getUTCHours().toString();
    //console.log("present-salt for", uid, ":", present_salt);
    return raw_hash('SHA256', raw_hash('MD5', conf.api_users_secret) + uid+present_salt);  
}

/** @type {<T extends object, K extends keyof T>(object: T, key: K) => T[K]} */
function getAndDelete(o, key) {
    const val = o[key]
    delete o[key]
    // @ts-ignore
    return val
}

/** @type {<T extends object, K extends keyof T>(object: T, ...paths: Array<K>) => Pick<T, K>} */
function pick(o, ...keys) {
    let r = {}
    for (const key of keys) {
        // @ts-ignore
        r[key] = o[key]
    }
    // @ts-ignore
    return r
}

module.exports = { seconds_since, get_hash, getAndDelete, pick }