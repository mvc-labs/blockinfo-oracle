import express = require('express')
import request = require('superagent')
import fs = require('fs')
const Rabin = require('./rabin/rabin')

const app = express()

const allowCors = function (req, res, next) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', ['Content-Type', 'Content-Encoding']);
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
};
app.use(allowCors)

const server: any = {}

server.app = app

let httpserver

const TIMEOUT = 120000 // 120s
const PUBKEY_LEN = 384

function getUInt32Buf(amount: number) {
    const buf = Buffer.alloc(4, 0)
    buf.writeUInt32LE(amount)
    return buf
}

function toBufferLE(num: BigInt, width: number) {
    const hex = num.toString(16);
    const buffer = Buffer.from(hex.padStart(width * 2, '0').slice(0, width * 2), 'hex');
    buffer.reverse();
    return buffer;
}

server.start = function (config) {

    if (!process.env.RABIN_P || !process.env.RABIN_Q) {
        throw Error('need rabin private key in env')
    }

    const rabinPrivateKey = {
        p: BigInt(process.env.RABIN_P),
        q: BigInt(process.env.RABIN_Q)
    }
    const rabinPubKey = Rabin.privKeyToPubKey(rabinPrivateKey.p, rabinPrivateKey.q)
    const rabinPubKeyhex = toBufferLE(rabinPubKey, PUBKEY_LEN).toString('hex')

    app.get('/', async function(req, res) {
        const blockRes = await request.get(
            `https://api.sensiblequery.com/blockchain/info`
        ).timeout(TIMEOUT)
        if (blockRes.status !== 200 || blockRes.body.code !== 0) {
            console.log('getBlockHeight failed: ',res, res.body)
            res.json({code: 1, msg: 'getBlockHeight failed'})
            return
        }
        const blockData = blockRes.body.data
        const blockHeight = blockData.blocks - 1

        let userdata = Buffer.alloc(0)
        if (req.query.nonce) {
            userdata = Buffer.from(req.query.nonce, 'hex')
        }
        const rabinMsg = Buffer.concat([
            getUInt32Buf(blockHeight),
            getUInt32Buf(blockData.medianTime),
            Buffer.from(blockData.bestBlockHash, 'hex'), // block hash
            Buffer.from('426974636f696e205356', 'hex'),
            userdata,
        ])

        let rabinSignResult = Rabin.sign(rabinMsg.toString('hex'), rabinPrivateKey.p, rabinPrivateKey.q, rabinPubKey)
        const rabinSign = toBufferLE(rabinSignResult.signature, PUBKEY_LEN).toString('hex')
        const rabinPadding = Buffer.alloc(rabinSignResult.paddingByteCount, 0).toString('hex')

        const data = {
            "chain":"Bitcoin SV",
            "height": blockHeight,
            "median_time_past": blockData.medianTime, 
            "block": blockData.bestBlockHash,
            "timestamp": Math.floor(new Date().getTime() / 1000),
            "digest": rabinMsg.toString('hex'),
            "signatures":{
                "rabin":{
                    "public_key": rabinPubKeyhex,
                    "signature": rabinSign,
                    "padding": rabinPadding,
                }
            }
        }
        res.json({ code: 0, data })
    })

    httpserver = app.listen(config.port, config.ip, function () {
        console.log("start at listen %s:%s", config.ip, config.port)
    })
}

server.closeFlag = false

server.close = async function () {
    server.closeFlag = true
    await httpserver.close()
}

async function main() {
    const path = process.argv[2]
    const config = JSON.parse(fs.readFileSync(path).toString())
    server.start(config)
}

main()