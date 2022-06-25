const querystring = require('querystring')
const express = require('express');
const request = require('request');

const cond_no_otp = require('./cond_no_otp')
const h = require('./helpers')
const conf = require('../conf')


const html_remove_ticket_script = `<script>
window.history.replaceState({}, null, location.href.replace(/[?&]ticket=.*/, ''))
</script>`
const validateErrorXml = `<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
<cas:authenticationFailure code="INVALID_TICKET">
</cas:authenticationFailure>
</cas:serviceResponse>`;


const save_allowed_ticket = (sessionStore, ticket, info) => {
    if (!ticket) { console.trace(); throw "internal error" }
    //console.log('save_allowed_ticket', ticket, info)
    info.date = Date.now()
    sessionStore.set(ticket, info, (err) => {
        console.log("storing ticket", ticket, "done")
        if (err) console.error(err)
    })
    return ticket
}

const get_allowed_ticket = (sessionStore, service, ticket) => (
    new Promise((resolve, reject) => {
        sessionStore.get(ticket, (err, info) => {
            if (err) {
                console.error(err)
                return reject()
            }
            sessionStore.destroy(ticket) // only once
            if (!info) {
                console.error("unknown ticket", ticket, "(already validated?)")
            } else if (info.service !== service) {
                console.error("invalid service: at login= ", info.service, "  at validate= ", service)
            } else if (h.seconds_since(info.date) > conf.ticket_validity_seconds) {
                console.error("ticket expired", ticket, ": issued", h.seconds_since(info.date), "seconds ago")
            } else {
                console.log("ticket", ticket, "is valid for uid", info.uid)
                return resolve(info)
            }
            reject()
        })
    })
)

const verifyOtp = (uid, otp) => (
    new Promise((resolve, reject) => {
        console.log('verifyOtp', uid, otp)
        request({
            method: 'POST',
            auth: { bearer: conf.api_password },
            url: conf.api_url + 'protected/users/' + uid + '/' + otp + '/',
        }, function(error, response, body) {
            if (error) {
                console.error("error1")
            } else if (response.statusCode == 200 && body) {
                const infos = JSON.parse(body);
                if (infos && infos.code === 'Ok') return resolve()
                if (infos && infos.code === 'Error') return reject("Le code est invalide.")
                console.error("error2", body)
            } else {
                console.error("error3")
            }
            reject("Problème technique, veuillez ré-essayer plus tard.")
        })
    })
)

const casv1_validate_ticket = (service, ticket) => (
    new Promise((resolve, reject) => {
        const url = conf.cas_server_validating_password_base_url + '/validate?service=' + encodeURIComponent(ourUrl({ service })) + '&ticket=' + ticket
        request({ url }, function(error, response, body) {
            if (error) {
                console.error("error1")
            } else if (response.statusCode == 200 && body) {
                const [l1, l2] = body.split("\n")
                if (l1 === 'yes') return resolve({ uid: l2, raw_response: body })
                if (l2 === 'no') return reject({ msg: "error" })
                console.error("error2", body)
            } else {
                console.error("error3", response.statusCode)
            }
            reject({ msg: "Problème technique, veuillez ré-essayer plus tard." })
        })
    })
)
const casv2_validate_ticket = (service, ticket) => (
    new Promise((resolve, reject) => {
        const url = conf.cas_server_validating_password_base_url + '/serviceValidate?service=' + encodeURIComponent(ourUrl({ service }) + '&auth_checked') + '&ticket=' + ticket
        request({ url }, function(error, response, body) {
            if (error) {
                console.error("error1")
            } else if (response.statusCode == 200 && body) {
                const m = body.match(/<cas:authenticationSuccess>/) && body.match(/<cas:user>(.*?)<\/cas:user>/)
                if (m) return resolve({ uid: m[1], raw_response: body })
                const err = body.match(/<cas:authenticationFailure code="(.*)">(.*?)</)
                if (err) return reject({ code: err[1], msg: err[2], raw_response: body })
                console.error("error2", body)
            } else {
                console.error("error3", response.statusCode)
            }
            reject({ msg: "Problème technique, veuillez ré-essayer plus tard." })
        })
    })
)

// it is not clearly defined in CAS protocol specification, but it is needed!
// (cf "AbstractServiceFactory.cleanupUrl" in Jasig/Apereo CAS, or DefaultServiceComparator.java in Shibboleth IDP)
const cleanup_service_url = (service) => (
    service.replace(/;jsession[^?]*/, '')
)

const ourUrl = (query) => (
    conf.our_base_url + '/login?' + querystring.stringify(query)
)

function login_page(res, uid, ticket, error) {
    res.render('login.ejs', {
        error,
        ticket,
        params: JSON.stringify({
            apiUrl: conf.api_url,
            uid,
            userHash: h.get_hash(uid),
        }),
    })
}

function rememberMe_page(res, ticket) {
    res.render('rememberMe.ejs', { ticket })
}

async function get_logged_user_in_session(session, service, ticket) {
    const user_and_ = await casv2_validate_ticket(service, ticket);
    console.log("used ticket", ticket, "to know the logged user. Saving ticket and response ");
    session.uid = user_and_.uid;
    if (!session.ticket_to_v2_raw_response)
        session.ticket_to_v2_raw_response = {};
    session.ticket_to_v2_raw_response[ticket] = user_and_.raw_response;
}

function require_a_ticket(res, service, gateway) {
    const redirectURL = conf.cas_server_validating_password_base_url + '/login?service=' + encodeURIComponent(ourUrl({ service }) + '&auth_checked') + (gateway ? '&gateway=true' : '');
    return res.redirect(redirectURL);
}

function onLoginSuccess(req, res, ticket) {
    const service = req.query.service
    if (!ticket) {
        return require_a_ticket(res, service, req.query.gateway);
    }
    let ticket_info = { uid: req.session.uid, service }
    // if we already validated this ticket, use it
    ticket_info.v2_raw_response = h.getAndDelete(req.session.ticket_to_v2_raw_response || {}, ticket)

    save_allowed_ticket(req.sessionStore, ticket, ticket_info);

    if (service) {
        res.redirect(service + (service.includes("?") ? "&" : "?") + "ticket=" + encodeURIComponent(ticket));
    } else {
        res.send("Utilisateur correctement authentifié");
    }
}

function routing() {
    let router = express.Router();

    router.get('/login', async function(req, res) {
        if (!req.session.cookie.originalMaxAge) {
            // increase validity, the default ttl is the one for saved tickets
            req.session.cookie.maxAge = conf.otp_validity_seconds * 1000
        }
    
        const ticket = req.query.ticket
        const service = req.query.service
        if (!req.session.uid) {
            if (req.query.gateway) {
                return res.redirect(service) // no way
            } else if (!ticket) {
                return require_a_ticket(res, service);
            } else {
                try {
                    await get_logged_user_in_session(req.session, service, ticket);
                } catch (err) {
                    console.error(err)
                    return res.send("erreur: " + err + html_remove_ticket_script)
                }
            }
        }

        try {
            if (req.query.ask == 'rememberMe') {
                rememberMe_page(res, ticket)
            } else if (req.session.validated_otp || await cond_no_otp.no_otp(req)) {
                if (!ticket && 'auth_checked' in req.query) {
                    return res.redirect(service) // back from password CAS with no ticket => it must be CAS gateway
                }
                onLoginSuccess(req, res, ticket)
            } else {
                login_page(res, req.session.uid, ticket, h.getAndDelete(req.session, 'error'));
            }
        } catch (err) {
            console.error(err)
            return res.send("erreur: " + err)
        }
    })

    router.post('/login', function(req, res) {
        if (req.body.logoutRequest) {
            if (require("ip-range-check")(req.ip, conf.allow_back_channel_single_logout.if_IP_in)) {
                // proxy SLO to application
                request({ url: req.query.service, method: 'POST', form: req.body })
            } else {
                console.error("ignoring SingleLogout request from IP", req.ip, " since it is not allowed in conf.allow_back_channel_single_logout.if_IP_in")
            }
            res.send('')
        } else if (req.body.rememberMe && req.session.validated_otp) {
            req.session.long_term_otp = req.body.rememberMe !== 'skip'
            if (req.session.long_term_otp) {
                // set cookie & session validity
                req.session.cookie.maxAge = conf.otp_long_term_validity_seconds * 1000
            }
            onLoginSuccess(req, res, req.body.ticket);
        } else if (req.body.token) {
            const uid = req.session.uid
            verifyOtp(uid, req.body.token).then(() => {
                req.session.validated_otp = Date.now()
                // will set session storage validity
                req.session.cookie.maxAge = conf.otp_validity_seconds * 1000

                res.redirect(ourUrl({ ...h.pick(req.query, 'service', 'renew'), ask: 'rememberMe', ticket: req.body.ticket }))
            }).catch(err => login_page(res, uid, req.body.ticket, err))
        } else {
            req.session.error = "La session avait expiré, veuillez recommencer" // ??
            res.redirect(ourUrl(h.pick(req.query, 'service', 'renew')))
        }
    })
    
    router.get('/validate', async function (req, res) {
        try {
            const ticket = req.query.ticket
            const service = cleanup_service_url(req.query.service) // we must simplify service URL before comparison & before sending to cas_server_validating_password (because it will be encoded => not ignored)
            const ticket_info = await get_allowed_ticket(req.sessionStore, service, ticket)
            if (!ticket_info.v2_raw_response) {
                console.log("proxying ticket validation v1", ticket)
                const user_and_ = await casv1_validate_ticket(service, ticket)
                if (user_and_.uid !== ticket_info.uid) throw "weird..."
            }
            res.send("yes\n" + ticket_info.uid + "\n")
        } catch (err) {
            res.send("no\n\n")
        }
    })

    router.get('/serviceValidate', async function (req, res) {
        res.header('Content-Type', 'application/xml; charset=UTF-8')
        try {
            const ticket = req.query.ticket
            const service = cleanup_service_url(req.query.service) // we must simplify service URL before comparison & before sending to cas_server_validating_password (because it will be encoded => not ignored)
            const ticket_info = await get_allowed_ticket(req.sessionStore, service, ticket)
            if (!ticket_info.v2_raw_response) {
                console.log("proxying ticket validation v2", ticket)
                const user_and_ = await casv2_validate_ticket(service, ticket)
                if (user_and_.uid !== ticket_info.uid) throw "weird..."
                ticket_info.v2_raw_response = user_and_.raw_response
            }
            res.send(ticket_info.v2_raw_response)
        } catch (err) {
            console.error(err)
            res.send(validateErrorXml)
        }
    })

    return router
}

module.exports = routing;
