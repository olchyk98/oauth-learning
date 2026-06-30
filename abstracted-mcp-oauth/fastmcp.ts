import { FastMCP, OAuthProvider } from 'fastmcp'

const server = new FastMCP({
  auth: new OAuthProvider({
    authorizationEndpoint: '/authorization',
    baseUrl: 'http://localhost:3999',
    clientId: 'clientId',
    clientSecret: 'clientSecret',
    scopes: ['openid', 'profile'],
    tokenEndpoint: '/token',
  }),
  name: 'Test MCP Oauth Server',
  version: '1.0.0',
})

await server.start({
  transportType: 'httpStream',
  httpStream: {
    port: 8080,
  },
})

console.log('MCP SERVER RUNNING')
