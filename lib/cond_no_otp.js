const request = require('request');
const h = require('./helpers')
const conf = require('../conf');

/** @typedef {{ if_IP_in?: string[], if_service?: h.service_tests, if_not_service?: h.service_tests }} conds */

/** @template {conds} T 
  * @param {T} conds
  * @param {string} msg */
function compute_no_otp_conds(req, conds, msg) {
    if (conds.if_IP_in) {
        if (require("ip-range-check")(req.ip, conds.if_IP_in)) {
            console.log(msg + " because of conds.if_IP_in for IP", req.ip)
            return true 
        }
    }
    if (req.query.service) {
        if (conds.if_service) {
            if (h.is_service_matching(conds.if_service, req.query.service)) {
                console.log(msg + " because of conds.if_service for service", req.query.service)
                return true
            }
        }
        if (conds.if_not_service) {
            if (!h.is_service_matching(conds.if_not_service, req.query.service)) {
                console.log(msg + " because of conds.if_not_service for service", req.query.service)
                return true
            }
        }
    }
    return false
}

/** @param {string} uid */
const otp_not_activated = (uid) => (
    new Promise((resolve, reject) => {
        const url = conf.api_url + '/users/'+ uid +'/' + h.get_hash(uid)
        request({ url }, function(error, response, body) {
            if (response.statusCode == 200 && body) {
                const data = JSON.parse(body)
                if (data?.code === 'Ok') {
                    const activated = Object.values(data.user.methods).some(e => e.active)
                    return resolve(!activated)
                }
            } else {
                console.error("error3", response.statusCode)
            }
            reject("Problème technique, veuillez ré-essayer plus tard.")
        })
    })
)    

async function no_otp(req) {
    if (compute_no_otp_conds(req, conf.no_otp, 'no OTP')) {
        return true
    }
    if (compute_no_otp_conds(req, conf.no_otp?.if_not_activated_for_user_and || {}, 'no OTP if not activated for user')) {
        if (await otp_not_activated(req.session.uid)) {
            console.log("no OTP for not activated user", req.session.uid, "and service", req.query.service)
            return true
        }
    }
    return false
}

module.exports = { no_otp }
