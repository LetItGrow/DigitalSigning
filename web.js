// web.js
var express = require("express");
var logfmt = require("logfmt");
var fs = require('fs');
var AWS = require('aws-sdk');
var bodyParser = require('body-parser');
var r = require('jsrsasign');

var app = express();

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
app.use(logfmt.requestLogger());

// parse application/json and application/x-www-form-urlencoded
app.use(bodyParser())


app.get('/', function (req, res) {
    res.sendfile('./info.html');
});

app.get('/sign', function (req, res) {
    res.sendfile('./sign.html');
});

app.get('/generate', function (req, res) {
    res.sendfile('./generate.html');
});

app.get('/tests', function (req, res) {
    res.sendfile('./tests.html');
});

app.get("/api/genkeys", function (req, res) {

    var keySize = req.query.keySize;
    if (!keySize) {
        keySize = "512";
    }
    var keyPair = r.KEYUTIL.generateKeypair("RSA", keySize);
//    var privKey = r.KEYUTIL.getKey(keyPair.prvKeyObj);
    var pubKey = r.KEYUTIL.getKey(keyPair.pubKeyObj);

    keyPair.prvKeyObj.isPrivate = true;
    var privateKey = r.KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS1PRV");
    var publicKey = r.KEYUTIL.getPEM(pubKey);

    var result = {"privateKey": privateKey, "publicKey": publicKey};
    res.send(JSON.stringify(result));
});

app.post('/api/uploadkey', function (req, res) {

    var username = req.body.username;
    var publicKey = req.body.publicKey;

    var result = {};
    var filename = "crts/" + username + ".crt";
    try {
        if (process.env.AWS_ACCESS_KEY_ID) {
            var s3 = new AWS.S3();
            s3.client.putObject({
                    Bucket: "sloydev-digitalsign",
                    Key: filename,
                    Body: publicKey
                },
                function (err, data) {
                    if (err) {
                        console.log(err, err.stack);
                        result.error = err;
                    } else {
                        result.ok = true;
                        console.log("Uploaded " + filename + " to S3");
                    }
                    res.send(JSON.stringify(result));

                });

        } else {
            fs.writeFileSync("./" + filename, publicKey);
            result.ok = true;
            res.send(JSON.stringify(result));
        }


    }
    catch (err) {
        result.error = err;
        console.log(err);
        res.send(JSON.stringify(result));
    }

//    for(var i =0;i<500000000;i++) {
//    }
});

app.post('/api/verify', function (req, res) {
    var username = req.body.username;
    var message = req.body.message;
    var signature = req.body.signature;
    var filename = "crts/" + username + ".crt";

    var verify = function (pubKey) {
        var response = {};
        if (pubKey) {
            var publicKey = r.KEYUTIL.getKey(pubKey);
            var sig = new r.Signature({"alg": "SHA256withRSA", "prov": "cryptojs/jsrsa"});
            sig.initVerifyByPublicKey(publicKey);
            sig.updateString(message);

            var isValid = sig.verify(signature);

            response = {"isValid": isValid};
        } else {
            response = {"error": true};
        }
        res.send(JSON.stringify(response));
    };

    if (process.env.S3_ACCESS_KEY_ID) {
        var s3 = new AWS.S3();
        s3.client.getObject({
                Bucket: "sloydev-digitalsign",
                Key: filename
            },
            function (err, data) {
                if (err) {
                    console.log(err, err.stack);
                    res.send(JSON.stringify({"error": err}));
                } else {
                    console.log("Readed " + filename + " from S3");
                    verify(data.Body.toString())
                }

            });
    } else {
        try {
            var publicKeyString = fs.readFileSync("./" + filename, 'utf8');
            verify(publicKeyString);

        } catch (err) {
            console.log(err);
            res.send(JSON.stringify({"error": err}));
        }

    }
});

app.get(/^(.+)$/, function (req, res) {
    res.sendfile('./public' + req.params[0]);
});

var port = Number(process.env.PORT || 5000);
app.listen(port, function () {
    console.log("Listening on " + port);
});