import express from 'express'
import * as oidc from 'oidc-provider'

class Adapter implements oidc.Adapter  {
  async upsert(id: string, payload: oidc.AdapterPayload, expiresIn: number): Promise<undefined | void> {
    return
  }
  async find(id: string): Promise<oidc.AdapterPayload | undefined | void> {
    return {}
  }
  async findByUserCode(userCode: string): Promise<oidc.AdapterPayload | undefined | void> {
    return {}
  }
  async findByUid(uid: string): Promise<oidc.AdapterPayload | undefined | void> {
    return {}
  }
  async consume(id: string): Promise<undefined | void> {
    return
  }
  async destroy(id: string): Promise<undefined | void> {
    return
  }
  async revokeByGrantId(grantId: string): Promise<undefined | void> {
    return
  }

}

const p = new oidc.Provider('http://localhost:3999', {
  adapter: Adapter,                              // <-- the "model"
  features: {
    registration: { enabled: true },             // RFC 7591 DCR  ->  POST /reg
    registrationManagement: { enabled: true },   // RFC 7592 read/update/delete (optional)
    introspection: { enabled: true },            // lets your MCP server validate tokens
  },
  pkce: { required: () => true },                // OAuth 2.1 / MCP: PKCE for every client
  async findAccount(ctx, sub) {                  // who a token represents
    return { accountId: sub, claims: async () => ({ sub }) };
  },
})

const app = express()

app.use(p.callback())

app.listen(3999, () => {
  console.log("AUTH SERVER RUNNING")
})
