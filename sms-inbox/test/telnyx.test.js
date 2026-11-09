import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyTelnyxWebhook } from '../src/telnyx.js';
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const publicKeyBase64=publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
function headers(body,timestamp=String(Math.floor(Date.now()/1000))){return {'telnyx-signature-ed25519':sign(null,Buffer.from(`${timestamp}|${body}`),privateKey).toString('base64'),'telnyx-timestamp':timestamp};}
test('accepts a correctly signed fresh webhook',()=>{const body=JSON.stringify({data:{event_type:'message.received'}});assert.equal(verifyTelnyxWebhook({rawBody:Buffer.from(body),headers:headers(body),publicKeyBase64}).valid,true);});
test('rejects a modified webhook body',()=>{const body='{}';assert.equal(verifyTelnyxWebhook({rawBody:Buffer.from('{ }'),headers:headers(body),publicKeyBase64}).valid,false);});
test('rejects stale timestamps',()=>{const body='{}';const stale=String(Math.floor(Date.now()/1000)-3600);assert.equal(verifyTelnyxWebhook({rawBody:Buffer.from(body),headers:headers(body,stale),publicKeyBase64}).valid,false);});
