const express = require("express");
const config = require("../../config.json")
const nanoid = require("nanoid")
const axios = require("axios")
const MEMBER = require("../../models/MEMBER")
var sanitize = require('mongo-sanitize');
const url = require("url");
const qs = require("qs")

var statelocaldb = []

const route = express.Router();

route.get("/", async (req, res) => {
    if (!req.query.redirect || req.query.redirect.toLowerCase().startsWith("http") == false) req.query.redirect = "https://eat-sleep-nintendo-repeat.eu/"
    if (req.query.redirect.split("//")[1].toLowerCase().startsWith("eat-sleep-nintendo-repeat.eu") == false) { res.status(400).send({error: "You used an redirect that could be redirecting you to malicious site. an attacker may successfully launch a phishing scam and steal user credentials"}); return;}

    //generate authentication state token
    let statedb = {code: nanoid.nanoid(10), verifier: nanoid.nanoid(64), method: "discord", "client_data.ip": req.headers['x-forwarded-for'] || req.ip || null, redirect: req.query.redirect}
    console.log("An AUTH started >", req.headers['x-forwarded-for'] || req.ip || null);

    //save state to local string
    statelocaldb.push(statedb)

    //encrypt code_verifyer
    const crypto = require('crypto');
    const code_challenge  = crypto.createHash('sha256').update(statedb.verifier).digest();

    //querystring
    let querystring = {
        client_id: config.discord_api.client_id,
        redirect_uri: `${config.devmode ? "http://192.168.178.31:5670" : "https://eat-sleep-nintendo-repeat.eu"}/api/auth/discord/callback`,
        response_type: "code",
        scope: "identify email",
        promt: "none",
        state: statedb.code,
        code_challenge: code_challenge.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        code_challenge_method: "S256",
    }

    //generate url
    res.redirect(`https://discord.com/api/oauth2/authorize?${qs.stringify(querystring)}`)
})

route.get("/callback", async (req, res) => {

    //#region check if state is valid
    let state_token = req.query.state
    let reqip = req.headers['x-forwarded-for'] || req.ip || null
    if (!state_token) return res.status(400).send("No state_authentication_token found")

    let statedb = statelocaldb.find(x => x.code == state_token)
    if (!statedb || statedb.method != "discord" || statedb.status.name != "started") return res.status(400).send("The state_authentication_token is invalid")

    if (statedb.client_data.ip && reqip) {
        if (reqip != statedb.client_data.ip) {
            res.status(400).send("The IP that was recordet while your state_authentication_token was generated does not match the ip you are using now")
            //remove state from local db
            return statelocaldb = statelocaldb.filter(x => x.code != state_token)
        }
    }

    //#endregion

    //#region check for discord errors
    if (req.query.error) {
        res.status(400).send("Discord Error")
        return statelocaldb = statelocaldb.filter(x => x.code != state_token)
    }
    //#endregion

    //#region exchange code to token
    if (!req.query.code) return res.status(400).send("missing code")

    var formData = new url.URLSearchParams({
        client_id: config.discord_api.client_id,
        client_secret: config.discord_api.client_secret,
        grant_type: "authorization_code",
        code: req.query.code,
        code_verifier: statedb.verifier,
        redirect_uri: `${config.devmode ? "http://192.168.178.31:5670" : "https://eat-sleep-nintendo-repeat.eu"}/api/auth/discord/callback`
    })

    const exchange_response = await axios.post("https://discord.com/api/oauth2/token",
                                    formData.toString(),
                                    {headers: {
                                        'Content-Type': 'application/x-www-form-urlencoded'
                                    }}).catch(async e => {
                                        console.log(e)
                                        res.status(500).send("An error has occurred while we tried to exchage your token");
                                        return statelocaldb = statelocaldb.filter(x => x.code != state_token)
                                    })

    if (!exchange_response || !exchange_response.data || !exchange_response.data.access_token) return;

    //#endregion
    
    //#region fetch userdata and check if access_code is valid
    axios.get("https://discord.com/api/oauth2/@me", {headers: {"Authorization": `Bearer ${exchange_response.data.access_token}`}}).then(async user_data_response => {
        user_data_response = user_data_response.data

        //check database
        var memberdb = await MEMBER.findOne({id: sanitize(user_data_response.user.id)})
        if (!memberdb) {
            res.send("You are not registered on this server")
            return statelocaldb = statelocaldb.filter(x => x.code != state_token)
        }

        //generate refresh_token and add to database storage
        var refresh_token = nanoid.nanoid(64)
        memberdb.oauth.cookies.push({refresh_token: refresh_token})
        if (5 < memberdb.oauth.cookies.length) {
            memberdb.oauth.cookies.shift();
          } //if there are more then 5 cookies registered, remove the oldest one from db

        //encrypt discord tokens
        const {createCipheriv, randomBytes} = require('crypto');
        const iv = randomBytes(16);
        const cipher_access = createCipheriv("aes256", config.eycryption_key, iv)
        const cipher_refresh = createCipheriv("aes256", config.eycryption_key, iv)

        //update database
        await MEMBER.findOneAndUpdate({id: sanitize(user_data_response.user.id)}, {
            informations: { name: user_data_response.user.username, discriminator: user_data_response.user.discriminator, avatar: user_data_response.user.avatar },
            "oauth.e_access_token": cipher_access.update(exchange_response.data.access_token, "utf-8", "hex") + cipher_access.final("hex"),
            "oauth.e_refresh_token": cipher_refresh.update(exchange_response.data.refresh_token, "utf-8", "hex") + cipher_refresh.final("hex"),
            "oauth.e_iv": iv,
            "oauth.scopes": user_data_response.scopes,
            "oauth.expire_date": new Date(user_data_response.expires),
            "oauth.cookies": memberdb.oauth.cookies
        })

        //save generated cookie to client cookie storage
        var cookieexpire = new Date();
        cookieexpire.setMonth(cookieexpire.getMonth() + 1)
        res.cookie("refresh_token", refresh_token, { expires: cookieexpire});

        //update state
        statelocaldb = statelocaldb.filter(x => x.code != state_token)
        res.redirect(doc.redirect)



    }).catch(async e => {
        res.status(400).send("Something went wrong while we tried to validate your auth tokens");
        returnstatelocaldb = statelocaldb.filter(x => x.code != state_token)
    })

    //#endregion





})

module.exports = route;
