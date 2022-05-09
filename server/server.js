const crypto = require("crypto");
// Importing the required modules
const WebSocketServer = require('ws');
 
// Creating a new websocket server
const wss = new WebSocketServer.Server({ port: 8080 })
const sockets = {}; 
// Creating connection using websocket
wss.on("connection", ws => {
    // sending message
    ws.on("message", data => {
        let json="";
        try {
            if (ws._socket.decipher !== undefined) {
                decipher = crypto.createDecipheriv('aes-256-cbc', ws._socket.aesKey, ws._socket.iv);
                data = Buffer.from(data,'base64').toString();
                decrypted = decipher.update(data,'base64','utf8');
                decrypted += decipher.final('utf8');
                data = decrypted;
            }
            json = JSON.parse(data);

        } catch (err) {
            console.log(err);
        }
        if (json.command == "broadcast") {
            if (ws._socket.decipher === undefined) {
                let answer = Buffer.from(JSON.stringify({"reply":"broadcast","error":1,"errorTXT":"You Must be encrypted to broadcast"}));
                ws.send(answer)
            } else {
                wss.clients.forEach(function each(client) {
                    let broadcast = {};
                    broadcast.command = "broadcast";
                    broadcast.message = json.message;
                    let cipher = crypto.createCipheriv('aes-256-cbc', client._socket.aesKey, client._socket.iv);
                    command = cipher.update(JSON.stringify(broadcast), 'utf8', 'base64');
                    command += cipher.final('base64');
                    answer = command;
                    client.send(answer);
                });
            }
        }

        if (json.command == "myid") {
            if (ws._socket.decipher === undefined) {
                let answer = Buffer.from(JSON.stringify({"reply":"sendid","error":1,"errorTXT":"You Must be encrypted to myid"}));
                ws.send(answer)
            } else {
                ws._socket.clientid = json.myid;
                ws._socket.idVerified = 0;
                console.log(json.myid);
            }
        }

        if (json.command == "sendPubKey") {
            if (ws._socket.decipher === undefined) {
                let answer = Buffer.from(JSON.stringify({"reply":"sendPubKey","error":1,"errorTXT":"You Must be encrypted to sendPubKey"}));
                ws.send(answer)
            } else {
                wss.clients.forEach(function each(client) {
                    if (json.chatFrom == client._socket.clientid) {
                        let setKey = {};
                        setKey.command = "setKey";
                        setKey.setTo = json.chatTo;
                        setKey.setKey = json.pubkey;
                        let cipher = crypto.createCipheriv('aes-256-cbc', client._socket.aesKey, client._socket.iv);
                        command = cipher.update(JSON.stringify(setKey), 'utf8', 'base64');
                        command += cipher.final('base64');
                        answer = command;
                        client.send(answer);
                    }
                });
            }
        }

        if (json.command == "chatTo") {
            if (ws._socket.decipher === undefined) {
                let answer = Buffer.from(JSON.stringify({"reply":"chatTo","error":1,"errorTXT":"You Must be encrypted to sendid"}));
                ws.send(answer)
            } else {
                console.log(json);
                wss.clients.forEach(function each(client) {
                    if (json.chatTo == client._socket.clientid) {
                        let pubKey = {};
                        pubKey.command = "getPubKey";
                        pubKey.chatFrom = ws._socket.clientid;
                        pubKey.chatTo = json.chatTo;
                        pubKey.chatFromPublicKey = json.chatFromPublicKey;
                        console.log(pubKey);
                        let cipher = crypto.createCipheriv('aes-256-cbc', client._socket.aesKey, client._socket.iv);
                        command = cipher.update(JSON.stringify(pubKey), 'utf8', 'base64');
                        command += cipher.final('base64');
                        answer = command;
                        client.send(answer);
                    }
                });
            }
        }
        if (json.command == "encrypt") {
            ws._socket.theirPublicKey=json.key;
            ws._socket.key=json.key;
            let iv = crypto.randomBytes(8).toString('hex');
            let key = crypto.randomBytes(16).toString('hex');
            ws._socket.iv=iv;
            ws._socket.aesKey=key;
            let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            ws._socket.decipher=decipher;
            ws._socket.cipher=cipher;
            let answer = {};
            answer.reply="aes";
            answer.iv = iv;
            answer.key = key;
            answer.encrypted = true;
            answer = crypto.publicEncrypt(ws._socket.theirPublicKey,Buffer.from(JSON.stringify(answer)));
            ws.send(answer);
        }
        if (json.command == "message") {
            wss.clients.forEach(function each(client) {
                if (json.to == client._socket.clientid) {
                    //no need to encrypt we are just passing it through.
                    let message = {};
                    message.command = json.command;
                    message.to = json.to;
                    message.from = json.from;
                    message.data = json.data;
                    console.log(message);
                    cipher = crypto.createCipheriv('aes-256-cbc', client._socket.aesKey, client._socket.iv);
                    command = cipher.update(JSON.stringify(message), 'utf8', 'base64');
                    command += cipher.final('base64');
                    answer = command;
                    client.send(answer);
                }
            });
        }

        if (json.command == "keySet") {
            wss.clients.forEach(function each(client) {
                if (json.to == client._socket.clientid) {
                    //no need to encrypt we are just passing it through.
                    let message = {};
                    message.command = json.command;
                    message.to = json.to;
                    message.from = json.from;
                    message.data = json.data;
                    console.log(message);
                    cipher = crypto.createCipheriv('aes-256-cbc', client._socket.aesKey, client._socket.iv);
                    command = cipher.update(JSON.stringify(message), 'utf8', 'base64');
                    command += cipher.final('base64');
                    answer = command;
                    client.send(answer);
                }
            });
        }

        if (json.command == "ping") {
            let answer = {"reply":"pong"};
            if (ws._socket.theirPublicKey !== undefined) {
                answer.encrypted=true;
                if (ws._socket.cipher !== undefined) {
                    cipher = crypto.createCipheriv('aes-256-cbc', ws._socket.aesKey, ws._socket.iv);
                    command = cipher.update(JSON.stringify(answer), 'utf8', 'base64');
                    command += cipher.final('base64');
                    answer = command;
                } else {
                    answer = crypto.publicEncrypt(ws._socket.theirPublicKey,Buffer.from(JSON.stringify(answer)));
                }
            } else {
                answer.encrypted=false;
                answer = JSON.stringify(answer);
            }
            ws.send(answer);
        }
    });
    // handling what to do when clients disconnects from server
    ws.on("close", () => {
        console.log("the client has disconnected");
    });
    // handling client connection error
    ws.onerror = function () {
        console.log("Some Error occurred")
    }
});
console.log("The WebSocket server is running on port 8080");
