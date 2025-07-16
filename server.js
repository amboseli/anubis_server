// server.js
// Copyright (C) 2025 James D. Marks
//
//    This file is part of Babase.
//
//    Babase is free software; you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation; either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with Babase.  If not, see <http://www.gnu.org/licenses/>.
//
//
// Syntax: See usage() below.
//
// James D. Marks <jim.marks@comcast.net>
//
// Bugs:
//
// server.js
const { handleGenerateKeys, decryptMessage } = require('./genpgpkeys.js');
const fs = require('fs');

const version = '2.15';
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const app = express();
const cors = require('cors');
const CryptoJS = require("crypto-js");
const cryptokey = 'noevildeedliveon'
const port = 3000;
const productionport = 5432
const developmentport = 5433
const useport = productionport

// Serve static files from the 'build' directory
app.use(express.static(path.join(__dirname, 'build')));

// Handle any route by serving the index.html file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

app.use(express.json());

/* ADDED FOR CORS RESOLUTION */

const corsOptions = {
	origin: ['https://ranker-dev.biology.duke.edu', 'http://localhost:3005', 'http://papio.biology.duke.edu:3005'], //Allow requests from this origin
      methods: 'GET,POST,PUT,DELETE', // Allowed methods
      allowedHeaders: 'Content-Type,Authorization', // Allowed headers
      credentials: true // Allow cookies
};
	
app.use(cors(corsOptions));

app.options('*', cors()); // Handle preflight requests for all routes

/* ADDED FOR CORS RESOLUTION */
//app.use(cors());

const packSuccessPayload = (response) =>
{
  const data = {}
  data.payload = response
  data.apihandshake = true
  return data
}

const packErrorPayload = (message, err) =>
  {
    const payload = {}
    payload.message = message
    payload.code = err ? err.code : -1
    payload.stack = err ? err.stack : 'no SQL exception raised'
  
    const data = {}
    data.payload = payload
    data.apihandshake = true
    return data
  }
// Health check
app.get('/api/', async (req, res) => {
  try {
    res.send('Ranker service v' + version + ' online');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

function fileErrorHandler(err){
    if (err) {
        console.error('Error:', err.message);
    } else {
        console.log('File written successfully.');
    }
}

// Generate PGP keys
app.get('/api/genkeys/:passphrase', async (req, res) => {
  fs.mkdirSync('./pgp', { recursive: true })
  const passphrase = req.params.passphrase
  fs.writeFileSync('./pgp/passphrase.txt', passphrase, { flag: 'w' })
  handleGenerateKeys(passphrase).then( newkeys => {
      fs.writeFileSync('./pgp/public-key.asc', newkeys.publicKey, { flag: 'w' })
      fs.writeFileSync('./pgp/private-key.asc', newkeys.privateKey, { flag: 'w' })
      // const publicKeyAsConst = 'export const publicKey = `' + newkeys.publicKey + '`'
      // fs.writeFileSync('./pgp/PublicKeyAsConst.js', publicKeyAsConst, { flag: 'w' })
    }
  )
  res.status(200).send('ok')
});

app.get('/api/getpublickey', async (req, res) => {
    try{
      const publicKey = fs.readFileSync('./public-key.asc', 'utf8')
      res.status(200).json(packSuccessPayload(publicKey));
    } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
    }
});

// GET endpoint to retrieve all ranks
app.get('/api/Ranks', async (req, res) => {
  const sessionpool = getSession(req)
  if(sessionpool){
    try {
      const client = await sessionpool.pool.connect();
      const result = await client.query('SELECT * FROM Ranks limit 10');
      client.release();
      res.json(packSuccessPayload(result.rows));
    } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
    }
  }
  else
  {
    res.setHeader('Set-Cookie', "rankersession={}; Max-Age=-99999999;" + "path=/;");
    res.status(500).send(packErrorPayload('Invalid session', undefined))
  }
});

app.post('/api/SQL', async (req, res) => {
  const sessionpool = getSession(req)
  if(sessionpool){
    const { sql } = req.body;
    //console.log(sql)
    try {
      const client = await sessionpool.pool.connect();
      const result = await client.query(sql);
      client.release();
      const data = {}
   res.status(200).json(packSuccessPayload(result.rows));
    } catch (err) {
      console.error(err);
      res.status(500).send(packErrorPayload('Server error', err));
    }
  }
  else
  {
    res.setHeader('Set-Cookie', "rankersession={}; Max-Age=-99999999;" + "path=/;");
    res.status(500).send(packErrorPayload('Invalid session', undefined))
  }
});

app.post('/api/saveranks', async (req, res) => {
  const sessionpool = getSession(req)
  if(sessionpool){
    const { deletepayload, insertpayload, deriveadultranks } = req.body;
    const client = await sessionpool.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(deletepayload.sql, [deletepayload.params.grp, deletepayload.params.rnktype, deletepayload.params.rnkdate]);
      for(let i = 0; i < insertpayload.params.ranking.length; i++){
        await client.query(insertpayload.sql, [insertpayload.params.ranking[i].sname, insertpayload.params.rnkdate, insertpayload.params.grp, insertpayload.params.rnktype, insertpayload.params.ranking[i].index+1]);
      }
      const primaryLog = 'PRIMARY: old ranks deleted. ' + String(insertpayload.params.ranking.length) + ' rows inserted.'
      let derivativeLog = undefined
      if(deriveadultranks)
      {
        const originalrnktype = insertpayload.params.rnktype
        const rnktype = originalrnktype.replace('L', 'D')
        const maturedSubset = insertpayload.params.ranking.filter(element => element.matured != null)
        const maturedRanking = maturedSubset.map(({sname}, index) => ({sname, index}))
        const resultadults = await client.query(deletepayload.sql, [deletepayload.params.grp,rnktype, deletepayload.params.rnkdate]);
        for(let i = 0; i < maturedRanking.length; i++){
          await client.query(insertpayload.sql, [maturedRanking[i].sname, insertpayload.params.rnkdate, insertpayload.params.grp, rnktype, maturedRanking[i].index+1]);
        }
        derivativeLog = 'DERIVATIVE: old ranks deleted. ' + String(maturedRanking.length) + ' rows inserted.'
      }
      await client.query('COMMIT');
      const log = derivativeLog ? primaryLog + ' ' + derivativeLog : primaryLog
      res.status(200).json(packSuccessPayload(log));
    } catch (err) {
       await client.query('ROLLBACK')
       res.status(500).send(packErrorPayload('Server error', err));
    }
    client.release();
  }
  else
  {
    res.setHeader('Set-Cookie', "rankersession={}; Max-Age=-99999999;" + "path=/;");
    res.status(500).send(packErrorPayload('Invalid session', undefined))
  }
});

/* AUTHENTICATION */

const pools = []

// PostgreSQL connection configuration
const addPool = (session, user, pwd, db, expires) => {
		const newpool = new Pool({
			host: 'localhost',
			user: user,
			password: pwd,
			database: db,
			port: useport
		})
		
		const poolsession = {}
		poolsession.session = session
		poolsession.expires = expires
    poolsession.user = user
    poolsession.database = db
		poolsession.pool = newpool
		
		pools.push(poolsession)

    //console.log('added session: ', poolsession.session)
}

const removePool = (session) => {
  const removeIndex = pools.findIndex(pool => pool.session === session)
  if(removeIndex >= 0)
  {
    pools.splice(removeIndex, 1)
  }
}

function getSession(req){
  const cookies = parseCookies(req.headers.cookie || '');
  const sessionCookie  = cookies.rankersession
  let sessionpool
  if(sessionCookie)
  {
    const rankersession = JSON.parse(sessionCookie)
    //console.log(sessionCookie, rankersession.user, rankersession.session)
    sessionpool = pools.find(pool => pool.session === rankersession.session)
  }
  return sessionpool
}

app.get('/api/sessionvalid', async (req, res) => {
  const sessionpool = getSession(req)
  //console.log('sessionpool', sessionpool)
  if(sessionpool){
    res.status(200).send('Valid session')
  }
  else
  {
    res.setHeader('Set-Cookie', "rankersession={}; Max-Age=-99999999;" + "path=/;");
    res.status(500).send('Invalid session')
  }
});

function parseCookies(cookieString) {
  const cookies = {};
  if (cookieString) {
    cookieString.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const key = parts.shift().trim();
      const value = parts.join('=').trim();
      cookies[key] = value;
    });
  }
  return cookies;
}

app.get('/api/testcookie', async (req, res) => {
	const now = new Date();
	now.setTime(now.getTime() + (4 * 60 * 60 * 1000)); // 4 hours in milliseconds
	const expires = "expires=" + now.toUTCString();
	const session = '03c32223-aacd-432f-afe2-87513112d622';
	const user = 'jdm187'
	const rankersession = JSON.stringify({session: session, user: user});
	//res.setHeader('Set-Cookie', "username=JimMarks;" + expires + ";path=/");
	res.setHeader('Set-Cookie', "rankersession=" + rankersession + ";" + expires + ";path=/");
	res.send('success')
});

app.get('/api/testcookiedelete', async (req, res) => {
	res.setHeader('Set-Cookie', "rankersession={}; Max-Age=-99999999;" + "path=/;");
	res.send('success')
});

app.get('/api/testsuccess', async (req, res) => {
  const response = {}
  response.apihandshake = 'true'
  response.data = 'testsuccess'
	res.status(200).send(response)
});
app.get('/api/testfailure', async (req, res) => {
  const response = {}
  response.apihandshake = 'true'
  response.data = 'testfailure'
	res.status(500).send(response)
});


app.post('/api/sessioncreate', async (req, res) => {
  //console.log(req.body)
  const origin = req.get('host')
  const session = crypto.randomUUID()
  const { user, pwd, database } = req.body
  
  const now = new Date();
  const expires = new Date();
	expires.setTime(expires.getTime() + (8 * 60 * 60 * 1000)); // 4 hours in milliseconds
	const expiresISO = expires.toISOString();
  const expiresUTC = expires.toUTCString();
	const rankersession = JSON.stringify({session: session, user: user});

  const decr = CryptoJS.AES.decrypt(pwd, 'noevildeedliveon');
  const passwordDecrypt = decr.toString(CryptoJS.enc.Utf8);

	addPool(session, user, passwordDecrypt, database, expiresISO)

  /* CLEAN UP SESSION POOLS */
  const inactivepools = pools.filter(pool => new Date(pool.expires) < now)
  inactivepools.forEach(pool => { 
    const inactivesession = pool.session; 
    removePool(inactivesession); 
    //console.log('removed inactive session: ', inactivesession)
  })
  /* END: CLEAN UP SESSION POOLS */  

  const sessionpool = pools.find(pool => pool.session === session)
  var status = false
  if(sessionpool)
  {
    try {
      const client = await sessionpool.pool.connect();
      const result = await client.query(
        `SELECT True HealthCheck`
      );
      client.release();
      //console.log(result)
      //console.log(pools)
      // for(let element of pools)
      // {
      //   console.log(element.session, element.expires, expiresISO)
      // }
      res.setHeader('Set-Cookie', "rankersession=" + rankersession + ";" + "expires='" + expiresUTC + "';"  + "path=/;" )
      res.status(201).json(packSuccessPayload("success"))
    } catch (err) {
      //console.log(err.routine)
      removePool(sessionpool.session)
      res.status(500).json(packErrorPayload(err, err))
    }
  }
});

app.post('/api/sessioncreatewithpgp', async (req, res) => {
  //console.log(req.body)
  const origin = req.get('host')
  const session = crypto.randomUUID()
  const { user, pwd, database } = req.body
  
  const now = new Date();
  const expires = new Date();
	expires.setTime(expires.getTime() + (8 * 60 * 60 * 1000)); // 4 hours in milliseconds
	const expiresISO = expires.toISOString();
  const expiresUTC = expires.toUTCString();
	const rankersession = JSON.stringify({session: session, user: user});

  const passwordDecrypt = await decryptMessage(pwd)

	addPool(session, user, passwordDecrypt, database, expiresISO)

  /* CLEAN UP SESSION POOLS */
  const inactivepools = pools.filter(pool => new Date(pool.expires) < now)
  inactivepools.forEach(pool => { 
    const inactivesession = pool.session; 
    removePool(inactivesession); 
    //console.log('removed inactive session: ', inactivesession)
  })
  /* END: CLEAN UP SESSION POOLS */  

  const sessionpool = pools.find(pool => pool.session === session)
  var status = false
  if(sessionpool)
  {
    try {
      const client = await sessionpool.pool.connect();
      const result = await client.query(
        `SELECT True HealthCheck`
      );
      client.release();
      //console.log(result)
      //console.log(pools)
      // for(let element of pools)
      // {
      //   console.log(element.session, element.expires, expiresISO)
      // }
      res.setHeader('Set-Cookie', "rankersession=" + rankersession + ";" + "expires='" + expiresUTC + "';"  + "path=/;" )
      res.status(201).json(packSuccessPayload("success"))
    } catch (err) {
      //console.log(err.routine)
      removePool(sessionpool.session)
      res.status(500).json(packErrorPayload(err, err))
    }
  }
});

/* END: AUTHENTICATION */

app.listen(port, () => {
  console.log(`Anubis Server v` + version + ` listening at http://localhost:${port}`);
});
