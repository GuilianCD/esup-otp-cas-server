const crypto = require('crypto');

const conf = require('../conf')


const seconds_since = (date) => (Date.now() - date) / 1000

function raw_hash(algo, data) {
    const hash = crypto.createHash(algo);
    hash.update(data)
    return hash.digest('hex')
}

function get_hash(uid) {
    const d = new Date();
    const present_salt = d.getUTCDate()+d.getUTCHours().toString();
    //console.log("present-salt for", uid, ":", present_salt);
    return raw_hash('SHA256', raw_hash('MD5', conf.api_users_secret) + uid+present_salt);  
}

function getAndDelete(o, key) {
    const val = o[key]
    delete o[key]
    return val
}

function pick(o, ...keys) {
    let r = {}
    for (const key of keys) {
        r[key] = o[key]
    }
    return r
}

module.exports = { seconds_since, get_hash, getAndDelete, pick }