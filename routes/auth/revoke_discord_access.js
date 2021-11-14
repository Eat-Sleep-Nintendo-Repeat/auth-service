const express = require("express");
const config = require("../../config.json");
const url = require("url");
const axios = require("axios");
const MEMBER = require("../../models/MEMBER");

const route = express.Router();

//revoke all tokens of the clients user
route.post("/", async (req, res) => {
    //check if refresh_token is valid
    var refresh_token = req.cookies.refresh_token
    if (!refresh_token) return res.status(401).send({error: "missing refresh_token"})

    var memberdb = await MEMBER.findOne({"oauth.cookies.refresh_token": refresh_token});
    if (!memberdb) return res.status(401).send({error: "invalid refresh_token"})

    //decrypt token
    const {createDecipheriv} = require('crypto');
    const decipher_refresh = createDecipheriv('aes256', config.eycryption_key, memberdb.oauth.e_iv);
    memberdb.oauth.refresh_token = decipher_refresh.update(memberdb.oauth.e_refresh_token, "hex", "utf-8") + decipher_refresh.final("utf-8")


    //revoke tokens
    var formData = new url.URLSearchParams({
        client_id: config.discord_api.client_id,
        client_secret: config.discord_api.client_secret,
        token: memberdb.oauth.refresh_token,
        token_type_hint: "refresh_token"
    })

    const revoke_response = await axios.post("https://discord.com/api/oauth2/token/revoke",
                                    formData.toString(),
                                    {headers: {
                                        'Content-Type': 'application/x-www-form-urlencoded'
                                    }}).catch(async e => {
                                        console.log(e)
                                    })
    
    if (revoke_response.status != 200) return res.status(500).send("An Error has occoured while we tried to revoke your oauth data");

    //remove auth_data from database
    await MEMBER.findOneAndUpdate({id: memberdb.id}, {
        "oauth.access_token": null,
        "oauth.refresh_token": null,
        "oauth.scopes": [],
        "auth.redirect": null,
        "oauth.cookies": [] 
    })

    //remove refresh_token from client cookie storage
    res.cookie("refresh_token", "**revoked due to revocation request**", { expires: new Date()});

    res.send({message: `All discord Oauth2 tokens that belonged to ${memberdb.informations.name} as well as every authentication tokens are revoked`})
})

module.exports = route;
