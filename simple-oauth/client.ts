import express from 'express'
import axios from 'axios'
import dedent from 'dedent'

const OAUTH_SERVICE_BASE_URL = 'http://localhost:3999'

const app = express()

// Page Gateway
app.get('/' , (req, res) => {
  res.status(200).send(
    dedent`
      <body>
        <b>:::CLIENT:::</b><br />
        <a href="/login-with-oauth">Login with OAuth</a>
      </body>
    `
  ).end()
})

// Once user presses "login", they get redirected here,
// and this handler automatically builds a request body
// compliant with OAUTH specification and sends it
// to the authorization service in question.
app.get('/login-with-oauth' , (req, res) => {
  const url = new URL(`${OAUTH_SERVICE_BASE_URL}/authorize`)

  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', 'this_is_me_client')
  url.searchParams.set('redirect_uri', 'http://localhost:4000/callback')
  url.searchParams.set('scope', 'everything:read')
  url.searchParams.set('state', 'the-word-is-red')

  res.redirect(url.href)
})

// The route that gets called by the Authorization Server
// containing the expected response. 
// In the fantasy world, this could genuinely 
// be the first call in the flow - but for that the
// authorization server to initiate contact and
// already know the details like client_id and redirect_uri (which it does).
// Usually this doesn't happen though, just indicates
// that this route doesn't have any dependency on
// the first redirect part (Client -> Authorization Server).
app.get('/callback' , async (req, res) => {
  const state = req.query.state as string
  const code = req.query.code as string

  console.log('Received state:', { state })

  const tokenURL = new URL(`${OAUTH_SERVICE_BASE_URL}/token`)
  tokenURL.searchParams.set('grant_type', 'authorization_code')
  tokenURL.searchParams.set('code', code)
  tokenURL.searchParams.set('redirect_uri', 'http://localhost:4000/callback')
  tokenURL.searchParams.set('client_id', 'this_is_me_client')
  tokenURL.searchParams.set('client_secret', 'this is my secret code')

  // Using the voucher (code) to obtain the accessToken
  const tokenResponse = await axios.post(tokenURL.href)
  const userResponse = await axios.get(`${OAUTH_SERVICE_BASE_URL}/api/user`, {
    headers: {
      Authorization: `Bearer ${tokenResponse.data.access_token}`
    }
  })

  if(tokenResponse.data.ok === false) {
    return res.send(
      dedent`
        <body>
          <b>:::CLIENT:::</b>
          <h1>The grant code could not be exchanged for an accessToken.</h1>
          <pre>${tokenResponse.data.message}</pre>
        </body>
      `
    ).status(200).end()
  }

  return res.send(
    dedent`
      <body>
        <b>:::CLIENT:::</b>
        <h1>Retrieved name: "${userResponse.data.name}"</h1>
        <pre>${JSON.stringify(tokenResponse.data, null, 2)}</pre>
      </body>
    `
  ).status(200).end()
})

app.listen(4000, () => {
  console.log("CLIENT RUNNING")
})
