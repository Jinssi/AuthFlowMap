// Minimal MCP server (Streamable HTTP transport, JSON responses only) protected per the MCP
// authorization spec: RFC 9728 protected resource metadata + WWW-Authenticate discovery.
// The incoming token is NEVER forwarded downstream; the server does its own OBO exchange.
import crypto from 'node:crypto';
import { validationEvent } from '../flows/obo.js';
import { readRunIdHeader, errorMessage, upstreamBody, q } from '../httpUtil.js';

export const PROTOCOL_VERSION = '2025-11-25';
const OBO_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

const WHOAMI_TOOL = {
  name: 'whoami',
  description: 'Returns the signed-in user profile from Microsoft Graph using the MCP server\'s own OBO token',
  inputSchema: { type: 'object', properties: {} },
};

function rpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: '2.0', id: id ?? null, error };
}

export function protectedResourceMetadata(cfg) {
  return {
    resource: cfg.mcpResource,
    authorization_servers: [cfg.issuerV2],
    scopes_supported: [cfg.scopes.mcp],
    bearer_methods_supported: ['header'],
    resource_name: 'AuthFlow demo MCP server',
  };
}

export function mountMcp(app, ctx) {
  const { cfg, trace, entra, validator } = ctx;

  const prm = (req, res) => res.json(protectedResourceMetadata(cfg));
  app.get('/.well-known/oauth-protected-resource/mcp', prm);
  app.get('/.well-known/oauth-protected-resource', prm);

  app.get('/mcp', (req, res) => {
    res.set('Allow', 'POST').status(405).json(rpcError(null, -32000, 'Method not allowed: this server does not offer an SSE stream'));
  });
  app.delete('/mcp', (req, res) => res.set('Allow', 'POST').status(405).end());

  app.post('/mcp', async (req, res) => {
    const runId = readRunIdHeader(req, res);
    if (runId === false) return;
    const msg = req.body;
    const id = msg && typeof msg === 'object' && !Array.isArray(msg) ? msg.id : null;

    const v = await validator.validateBearer(req, {
      expectedAudiences: cfg.mcpClientId ? [cfg.mcpClientId, `api://${cfg.mcpClientId}`] : [],
      requiredScope: 'mcp.tools',
    });
    if (!v.ok) {
      let challenge = `Bearer resource_metadata="${cfg.mcpResourceMetadata}", scope="${cfg.scopes.mcp}"`;
      if (!v.missing) {
        challenge += `, error="invalid_token", error_description="${q(v.error)}"`;
        trace.start(runId, 'mcp');
        trace.add(runId, validationEvent('mcp-validate', 'mcpserver', v, 'MCP server validates bearer token'));
        trace.finish(runId, v.error);
      }
      res.set('WWW-Authenticate', challenge);
      return res.status(401).json(rpcError(id, -32001, v.missing ? 'Unauthorized: bearer token required' : 'Unauthorized: invalid token'));
    }

    trace.start(runId, 'mcp');
    trace.add(runId, validationEvent('mcp-validate', 'mcpserver', v, 'MCP server validates bearer token'));

    if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      trace.finish(runId, 'Invalid JSON-RPC request');
      return res.status(400).json(rpcError(id, -32600, 'Invalid Request: expected a single JSON-RPC 2.0 message'));
    }

    const isNotification = !('id' in msg);
    try {
      if (isNotification) {
        trace.finish(runId);
        return res.status(202).end();
      }
      switch (msg.method) {
        case 'initialize': {
          res.set('Mcp-Session-Id', crypto.randomUUID());
          res.json({
            jsonrpc: '2.0', id,
            result: {
              protocolVersion: PROTOCOL_VERSION,
              capabilities: { tools: {} },
              serverInfo: { name: 'authflow-demo-mcp', version: '1.0.0' },
            },
          });
          break;
        }
        case 'ping':
          res.json({ jsonrpc: '2.0', id, result: {} });
          break;
        case 'tools/list':
          res.json({ jsonrpc: '2.0', id, result: { tools: [WHOAMI_TOOL] } });
          break;
        case 'tools/call': {
          const name = msg.params?.name;
          if (name !== 'whoami') {
            res.json(rpcError(id, -32602, `Unknown tool: ${String(name).slice(0, 64)}`));
            break;
          }
          if (!cfg.flows['mcp-obo']) {
            res.json(rpcError(id, -32603, 'MCP OBO not configured (MCP_CLIENT_SECRET missing)'));
            trace.finish(runId, 'MCP OBO not configured');
            return undefined;
          }
          const obo = await entra.tokenRequest(runId, {
            stepPrefix: 'mcp-obo', from: 'mcpserver', to: 'entra',
            labelReq: 'MCP server OBO exchange (own credentials)', labelRes: 'Graph token for the MCP server on behalf of the user',
            form: {
              grant_type: OBO_GRANT,
              client_id: cfg.mcpClientId,
              client_secret: cfg.mcpClientSecret,
              assertion: v.token,
              scope: 'https://graph.microsoft.com/User.Read',
              requested_token_use: 'on_behalf_of',
            },
          });
          const me = await entra.graphGet(runId, 'mcp-graph', 'mcpserver', 'graph', '/me', obo.access_token, {
            labelReq: 'GET /me (MCP server OBO token)', labelRes: 'User profile',
          });
          res.json({
            jsonrpc: '2.0', id,
            result: {
              content: [{ type: 'text', text: JSON.stringify({ displayName: me.displayName ?? null, userPrincipalName: me.userPrincipalName ?? null }) }],
            },
          });
          break;
        }
        default:
          res.json(rpcError(id, -32601, `Method not found: ${msg.method.slice(0, 64)}`));
      }
      trace.finish(runId);
    } catch (e) {
      // Upstream (Entra/Graph) failure: 502 with a JSON-RPC error carrying {error, error_description}.
      res.status(502).json(rpcError(id, -32603, errorMessage(e), upstreamBody(e)));
      trace.finish(runId, errorMessage(e));
    }
    return undefined;
  });
}
