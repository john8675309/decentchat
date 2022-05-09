const WebSocket = require('ws');
const crypto = require("crypto");
const fs = require("fs");

const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});

const chats = [];
const ivs = [];
const keys = [];

/* 
On Startup we want to read (or create) the public keys, this is to prove who this user is 
This will allow us to prove who we are to anyone we are talking to. and do a 2 way with unrusted servers in the middle
*/
if (!fs.existsSync("client.priv")) {
    console.log("Generating Your Network ID");
    let { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {modulusLength: 8192,publicKeyEncoding: { type:'pkcs1', format: 'pem'}, privateKeyEncoding: {type: 'pkcs1', format: 'pem' }});

    fs.writeFileSync('client.priv',privateKey.toString());
    fs.writeFileSync('client.pub',publicKey.toString());
}

const myPublicKey = fs.readFileSync('client.pub','utf-8');
const myPrivateKey = fs.readFileSync('client.priv','utf-8');
const myPublicKeyHash = crypto.createHash('sha256', '')
                              .update(myPublicKey)
                              .digest('hex');


const ws = new WebSocket("ws://localhost:8080");

function encrypt() {
    let { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {modulusLength: 4096,publicKeyEncoding: { type:'pkcs1', format: 'pem'}, privateKeyEncoding: {type: 'pkcs1', format: 'pem' }});
    let command = {'command':'encrypt','key':publicKey.toString()};
    ws._socket.privateKey = privateKey.toString();
    ws._socket.publicKey = publicKey.toString();
    ws.send(JSON.stringify(command));
}

function sendid() {
    let sendid = {};
    sendid.command = "myid";
    if (ws._socket.cipher !== undefined) {
        sendid.encrypted = true;
        sendid.myid=myPublicKeyHash;
        let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
        command = cipher.update(JSON.stringify(sendid), 'utf8', 'base64');
        command += cipher.final('base64');
        ws.send(command);
    } else {
        console.log("Must Be Encrypted");
    }
}
function connect() {
    encrypt();
    //sendid();
}
ws.addEventListener("open", () =>{
  connect();
  searchPrompt();
  ws.on("message", data => {
    try {

        if (ws._socket.privateKey !== undefined) {
            try {
                if (ws._socket.decipher !== undefined) {
                    let decipher = crypto.createDecipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                    data = Buffer.from(data,'base64').toString();
                    data = decipher.update(data, 'base64', 'utf8');
                    data += decipher.final('utf8');
                } else {
                    data = crypto.privateDecrypt(ws._socket.privateKey,data);
                }
            } catch (err) {
                console.log(err);
            }
        }
        try {
            data = JSON.parse(data);
        } catch (err) {
            console.log(err);
        }



        if (data.encrypted !== undefined) {
            if (data.encrypted == true) {
                if (data.reply == "aes") {
                    ws._socket.AESiv = data.iv;
                    ws._socket.AESkey = data.key;
                    let decipher = crypto.createDecipheriv('aes-256-cbc', data.key, data.iv);
                    let cipher = crypto.createCipheriv('aes-256-cbc', data.key, data.iv);
                    ws._socket.decipher = decipher;
                    ws._socket.cipher = cipher;
                    sendid();
                }
            }
        }
        if (data.reply == "pong") {
            console.log("Pong Encrypted: " + data.encrypted);
        }
        if (data.reply == "broadcast") {
            if (data.error > 0) {
                console.log(data.errorTXT);
            }
        }
        if (data.reply == "sendid") {
            if (data.error > 0) {
                console.log(data.errorTXT);
            }
        }
        if (data.command !== undefined) {
            if (data.command == "broadcast") {
                console.log(data.message);
            }
        }

        if (data.command !== undefined) {
            if (data.command == "getPubKey") {
                let sendPubKey = {};
                sendPubKey.command = "sendPubKey";
                sendPubKey.chatFrom = data.chatFrom;
                sendPubKey.chatTo = data.chatTo;
                sendPubKey.pubkey = myPublicKey;
                chats[data.chatFrom] = data.chatFromPublicKey;

                let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                command = cipher.update(JSON.stringify(sendPubKey), 'utf8', 'base64');
                command += cipher.final('base64');
                answer = command;
                ws.send(answer);
            }
            if (data.command == "keySet") {
                //this is probably a message with the keys
                newData = JSON.parse(crypto.privateDecrypt(myPrivateKey,Buffer.from(data.data)));
                if (newData.command == "keySet") {
                    ivs[newData.from] = newData.iv;
                    keys[newData.from] = newData.key;
                }
            }

            if (data.command == "message") {
                f = data.from;
                if (keys[data.from] === undefined) {
                    //this is probably a message with the keys
                        try {
                            newData = JSON.parse(crypto.privateDecrypt(myPrivateKey,Buffer.from(data.data)));
                            if (newData.command == "setKeys") {
                                ivs[newData.from] = newData.iv;
                                keys[newData.from] = newData.key;
                            }
                        } catch (err) {
                            var chatTo = {};
                            chatTo.command = "chatTo";
                            if (ws._socket.cipher !== undefined) {
                                chatTo.chatTo = f;
                                chatTo.chatFromPublicKey = myPublicKey;
                                let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                                command = cipher.update(JSON.stringify(chatTo), 'utf8', 'base64');
                                command += cipher.final('base64');
                                ws.send(command);
                                console.log("Warning Keys Have Been Regenerated Last Message From " + f + "May Not Have Arrived");
                            }
                        }
                } else {
                    //use the aes key
                    try {
                        let decipher = crypto.createDecipheriv('aes-256-cbc', keys[data.from], ivs[data.from]);
                        data = Buffer.from(data.data,'base64');
                        data = decipher.update(data, 'base64', 'utf8');
                        data += decipher.final('utf8');
                        newData = JSON.parse(data);
                        if (newData.command == "message") {
                            console.log("Message From " + newData.from + ": " + newData.message);
                        }
                    } catch (err) {
                        var chatTo = {};
                        chatTo.command = "chatTo";
                        if (ws._socket.cipher !== undefined) {
                            chatTo.chatTo = f;
                            chatTo.chatFromPublicKey = myPublicKey;
                            let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                            command = cipher.update(JSON.stringify(chatTo), 'utf8', 'base64');
                            command += cipher.final('base64');
                            ws.send(command);
                            console.log("********************Warning Keys Have Been Regenerated Last Message May Have Not Arrived***************************");
                        }
                    }
                }

            }
            if (data.command == "setKey") {
                let sendPubKey = {};
                chats[data.setTo] = data.setKey;
                let Civ = crypto.randomBytes(8).toString('hex');
                let Ckey = crypto.randomBytes(16).toString('hex');
                let shared = {};
                shared.iv = Civ;
                shared.key = Ckey;
                shared.from = myPublicKeyHash;
                shared.command = "keySet";
                ivs[data.setTo] = Civ;
                keys[data.setTo] = Ckey;
                shared = crypto.publicEncrypt(data.setKey,Buffer.from(JSON.stringify(shared)));
                let message = {};
                message.command = "keySet";
                message.to = data.setTo;
                message.from = myPublicKeyHash;
                message.data = shared;
                let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                command = cipher.update(JSON.stringify(message), 'utf8', 'base64');
                command += cipher.final('base64');
                answer = command;
                ws.send(answer);
            }
        }


    } catch (err) {
        console.log(err);
    }
  });
});

function inMessage(messageTo) {
    readline.question('['+messageTo+']: ', message => {
        if (message == 'exit') {
            searchPrompt();
        }
        let userMessage = {};
        userMessage.command = "message";
        userMessage.message = message;
        userMessage.to = messageTo;
        userMessage.from = myPublicKeyHash;

        let cipher = crypto.createCipheriv('aes-256-cbc', keys[messageTo], ivs[messageTo]);
        command = cipher.update(JSON.stringify(userMessage), 'utf8', 'base64');
        command += cipher.final('base64');

        let toSend = {};
        toSend.command = "message";
        toSend.to = messageTo;
        toSend.from = myPublicKeyHash;
        toSend.data = command;
        cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
        command = cipher.update(JSON.stringify(toSend), 'utf8', 'base64');
        command += cipher.final('base64');


        //console.log("To " + messageTo + ": " + message);
        ws.send(command);
        inMessage(messageTo);
    });
}

function searchPrompt() {
  readline.question('> ', input => {
    if( input == 'exit' ) {
      readline.close();
      process.exit(1);
    }

    if (input == 'help') {
        console.log("me.......................................Show My Public Hash");
        console.log("broadcast................................Send A Message To All Nodes (will be removed later)");
        console.log("ping.....................................Send A ping packet to the server should get a pong response");
        console.log("encrypt..................................Generate a public private key pair for this server session in order to pass the iv and aes key");
        console.log("serverPublicKey..........................Show The Servers Public Key");
        console.log("myPublicKey..............................Show My Public Key");
        console.log("message..................................Start Sending A Message");
        console.log("sendid...................................Send My Public Hash To The Server");
        console.log("chat.....................................Start A Chat Trade Keys And Setup A Secret Key");
        console.log("listchats................................List All Of The Shared Keys");
        console.log("--------------------------------------------------------------------------------------------------------------------------------------");
        console.log("Example Session");
        console.log("> encrypt");
        console.log("> sendid");
        console.log("> chat");
        console.log("Chat To: b736b5c3745b95a5c126853b6a5ad00c37c4457034cbce3ae28443829d4d5b01");
        console.log("> message");
        console.log("To: b736b5c3745b95a5c126853b6a5ad00c37c4457034cbce3ae28443829d4d5b01");
        console.log("Message: Test");
        console.log("To b736b5c3745b95a5c126853b6a5ad00c37c4457034cbce3ae28443829d4d5b01: Test");
        console.log("[b736b5c3745b95a5c126853b6a5ad00c37c4457034cbce3ae28443829d4d5b01]: Hi");
        console.log("[b736b5c3745b95a5c126853b6a5ad00c37c4457034cbce3ae28443829d4d5b01]: exit");
        console.log("> ");
        console.log("--------------------------------------------------------------------------------------------------------------------------------------");
    }
    if (input == 'listchats') {
        console.log(chats);
        console.log("---------------------------------------------------------");
        console.log(ivs);
        console.log("---------------------------------------------------------");
        console.log(keys);
    }

    if (input == 'me') {
        console.log(myPublicKeyHash);
    }
    if (input == "chat") {
        readline.question('Chat To: ', vChatTo => {
            var chatTo = {};
            chatTo.command = "chatTo";
            if (ws._socket.cipher !== undefined) {
                chatTo.chatTo = vChatTo;
                chatTo.chatFromPublicKey = myPublicKey;
                let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                command = cipher.update(JSON.stringify(chatTo), 'utf8', 'base64');
                command += cipher.final('base64');
                ws.send(command);
                searchPrompt();
            } 
        });
    }


    if (input == "message") {
        readline.question('To: ', messageTo => {
            readline.question('Message: ', message => {
                let userMessage = {};
                userMessage.command = "message";
                userMessage.message = message;
                userMessage.to = messageTo;
                userMessage.from = myPublicKeyHash;

                let cipher = crypto.createCipheriv('aes-256-cbc', keys[messageTo], ivs[messageTo]);
                command = cipher.update(JSON.stringify(userMessage), 'utf8', 'base64');
                command += cipher.final('base64');

                let toSend = {};
                toSend.command = "message";
                toSend.to = messageTo;
                toSend.from = myPublicKeyHash;
                toSend.data = command;
                cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
                command = cipher.update(JSON.stringify(toSend), 'utf8', 'base64');
                command += cipher.final('base64');


                console.log("To " + messageTo + ": " + message);
                ws.send(command);
                inMessage(messageTo);
                searchPrompt();
            });
        });
    }

    if (input == "sendid") {
        sendid();
    }

    if (input == "serverPublicKey") {
        if (ws._socket.publicKey !== undefined) {
            console.log(ws._socket.publicKey);
        } else {
            console.log("No Server Key Defined");
        }
    }

    if (input == "myPublicKey") {
        if (myPublicKey !== undefined) {
            console.log(myPublicKey);
        } else {
            console.log("No Public Key Defined");
        }
    }

    if (input == 'broadcast') {
        let command = "";
        let broadcast = {'command':'broadcast'};
        broadcast.message = "Hello World!";
        if (ws._socket.cipher !== undefined) {
            broadcast.encrypted = true;
            let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
            command = cipher.update(JSON.stringify(broadcast), 'utf8', 'base64');
            command += cipher.final('base64');
        } else {
            broadcast.encrypted = false;
            command = JSON.stringify(broadcast);
        }
        ws.send(command);
    }
    if (input == 'ping') {
        let command = "";
        let ping = {'command':'ping'};
        if (ws._socket.cipher !== undefined) {
            ping.encrypted = true;
            let cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.AESkey, ws._socket.AESiv);
            command = cipher.update(JSON.stringify(ping), 'utf8', 'base64');
            command += cipher.final('base64');
        } else {
            ping.encrypted = false;
            command = JSON.stringify(ping);
        }
        ws.send(command);
    }

    if (input == 'encrypt') {
        encrypt();
    }

    searchPrompt();
  });
}
