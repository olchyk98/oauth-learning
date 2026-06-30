import express from 'express'
import dedent from 'dedent'

const app = express()

interface Pending {
  redirectURI: string
  state: string
  scope: string
  clientID: string
  responseType: string
}

// OAUTH in it's basic format encourages/forces the authorization
// server to ask the clients that want to use OAUTH to register 
// their apps with them. Client goes to admin dashboard (like Google),
// creates an app - gets client_id and client_secret. client_id
// is used on each step, while client_secret is used for when
// the client exchanges code for accessToken - ensuring that
// at the end the client_id (which is usually not that secret) is not stolen 
// and we give access token to the service that has actually registered with us.
//
// For cases where client is not secure (like a web browser,
// or is dynamic (not really a persistent app) there are extensions
// PCKE (solving for client_secret part) and DCR (solving for 
// client_id part), which are covered in other folders in this repository.
//
// clientId => clientSecret
const registeredClients: Record<string, string> = {
  this_is_me_client: 'this is my secret code',
}

// Saving the redirectURI, state, scope
// and received input values - so it can
// be retrieved again when using confirming.
//
// This makes the /authorize call (which renders confirm
// button) enforced, as /authorize/confirm doesn't
// take same input as /authorize, but rather requestId
// generated at /authorize. 
//
// This way, some random page (page built by a hacker) 
// cannot just randomly redirect you to Google and
// obtain your information without you explicitly pressing "confirm".
//
// This works a nice "security" measure.
// It's not about Man in the Middle attack, it's
// about ensurring that you are a human who presses on the
// button on the page, and not just some random services
// redirecting you and you're not getting a question "You confirm?"
// before the Authrization service gives the accessToken
// with ability to read any data it wanted (specified through scope).
//
// requestId => Pending
const pending: Record<string, Pending> = {}

// Once user has accepted to login, we generate
// a code that client service can use to get
// an access token later.
//
// requestId => code
const codes: Record<string, string> = {}

// The one-time voucher (code) can be exchanged
// for the accessToken. The access token is used
// to perform the requests. It's kind of obvious,
// but since I started documenting, I thought I'd
// annotate this one as well.
const accessTokens = new Set()

// Page Gateway (If user approves, we'll just redirect
// to next empty page which will just generate code and redirect
// back to the original client).
app.get('/authorize' , (req, res) => {
  const clientID = req.query.client_id as string

  if(registeredClients[clientID] == null) {
    return res.send({
      ok: false,
      message: 'Invalid clientId.'
    }).status(401).end()
  }

  const requestId = Math.random().toString(16)
  pending[requestId] = {
    redirectURI: req.query.redirect_uri as string,
    state: req.query.state as string,
    scope: req.query.scope as string,
    clientID: req.query.client_id as string,
    responseType: req.query.response_type as string
  }

  // NOTE: In reality, we also want CSRF verification
  // here, so that hackers cannot forge 
  // One way to do it here is to generate a random 
  // key, set it to session, and then give it to 
  // client (through href here, through form potentially).
  // But since I'm just learning, not doing it here, and instead
  // of POST form I do GET, since it's easier.
  res.status(200).send(
    dedent`
      <body>
        <b>:::SERVER:::</b><br />
        <h1>Client "${clientID}" wants to read everything. Allow?</h1>
        <a href="/authorize/confirmed?requestId=${requestId}">Yes</a>
      </body>
    `
  ).end()
})

// Page for when user has confirmed and all
// we need is a code that we can send back.
// Empty page that just generates code and then 
// redirects back using redirectURI from original request.
app.get('/authorize/confirmed' , (req, res) => {
  // Also in this handler we'd verify scopes
  // and if clientId is registered with us and allowed.
  // But for simplicity, we skip that here.

  const requestId = req.query.requestId as string
  const request = pending[requestId]

  if(request == null) {
    return res.send({
      ok: false,
      message: 'Invalid requestId.'
    }).status(401).end()
  }

  // This code will be used to get accessToken on the next step.
  // Because redirecting user is GET, sending accessToken 
  // through that is leaky. It stays in browser history,
  // and is easily compromised. 
  // Therefore "code" is a single time voucher
  // which can be exchanged for an accessToken 
  // using a POST request (see "/token" route).
  const code = Math.random().toString(16)
  codes[requestId] = code

  const url = new URL(request.redirectURI)
  url.searchParams.set('state', request.state)
  url.searchParams.set('code', code)

  res.redirect(url.href)
})

// Now the client can use retrieved "code" (one time voucher),
// to exchange it for accessToken, by calling this route.
// Called with code, returns accessToken.
// Code gets terminated afterwards.
app.post('/token', (req, res) => {
  // The "grantType" & "clientID" & "redirectURI" 
  // are all required to be sent for basic verification purposes.
  // Just to ensure that the reuqest is coming from
  // the client we are expecting. Usually, there's
  // some verification, but here we'll skip that.
  const grantType = req.query.grant_type
  const clientId = req.query.client_id
  const clientSecret = req.query.client_secret
  const redirectURI = req.query.redirect_uri

  const code = req.query.code
  const requestId = Object.keys(codes).find((riq) => codes[riq] === code)
  if(requestId == null) {
    return res.send({
      ok: false,
      message: 'Invalid code.'
    }).status(401).end()
  }

  // This is the last step - getting accessToken,
  // so we have to verify that client_id they used all
  // along is actually matching the client_secret they
  // have supplied. Ensuring that the client is really
  // who they claim to be through client_id.
  if(pending[requestId]!.clientID !== clientId) {
    return res.send({
      ok: false,
      message: 'Supplied clientID does not match the one specified during the first step ("/authorize").'
    }).status(401).end()
  }


  if(registeredClients[clientId] !== clientSecret) {
    return res.send({
      ok: false,
      message: 'Specified clientSecret is not correct for the specified clientID.'
    }).status(401).end()
  }
  
  const scope = pending[requestId]!.scope
  const accessToken = `access_token_${Math.random().toString(16)}`
  accessTokens.add(accessToken)

  delete pending[requestId]
  delete codes[requestId]

  res.send({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope,
  }).status(200).end()
})

// And now the client can use accessToken
// to actually perform requests, like this one to
// retrieve username.
app.get('/api/user', (req, res) => {
  const authorization = req.headers['authorization'] as string
  const accessToken = authorization.slice(7)
  if(!accessTokens.has(accessToken)) {
    return res.send({
      ok: false,
      message: 'Invalid access token.'
    }).status(401).end()
  }
  return res.send({
    name: 'You! The User!'
  }).status(200).end()
})

app.listen(3999, () => {
  console.log("AUTHORIZATION SERVICE RUNNING")
})


