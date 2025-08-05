import express, { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { McpServer } from '../../server/mcp.js';
import { StreamableHTTPServerTransport } from '../../server/streamableHttp.js';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthMetadataRouter } from '../../server/auth/router.js';
import { requireBearerAuth } from '../../server/auth/middleware/bearerAuth.js';
import {
  CallToolResult,
  ElicitationRequiredError,
  ElicitRequestURLParams,
  ElicitResult,
  ErrorCode,
  isInitializeRequest,
  McpError,
  PrimitiveSchemaDefinition,
  ProgressNotification,
  ProgressToken,
} from '../../types.js';
import { InMemoryEventStore } from '../shared/inMemoryEventStore.js';
import { setupAuthServer } from './demoInMemoryOAuthProvider.js';
import { OAuthMetadata } from 'src/shared/auth.js';
import { checkResourceAllowed } from 'src/shared/auth-utils.js';

import cors from 'cors';
import { ElicitTrackHandler } from '../../server/index.js';

// Check for OAuth flag
const useOAuth = process.argv.includes('--oauth');
const strictOAuth = process.argv.includes('--oauth-strict');

// Create an MCP server with implementation details
const getServer = () => {
  const server = new McpServer({
    name: 'simple-streamable-http-server',
    version: '1.0.0',
  }, {
    capabilities: { logging: {} },
    onElicitTrack: trackElicitation,
  });

  server.tool(
    'payment-confirm',
    'A tool that confirms a payment directly with a user',  // description
    {
      cartId: z.string().describe('The ID of the cart to confirm'),
    },
    async (_args, _extra): Promise<CallToolResult> => {
      /*
        In a real world scenario, there would be some logic here to check if the user has the provided cartId.
        Auth info (with a subject or `sub` claim) can be typically be found in `extra.authInfo`.
        If we do, we can just return the result of the tool call.
        If we don't, we can throw an ElicitationRequiredError to request the user to upgrade.
        For the purposes of this example, we'll just throw an error.

        In this example, we show when the server is unable to provide tracking of the elicitation.
        On the server side, we simply do not track the elicitationId. The client will receive an InvalidParams error.
      */

      throw new ElicitationRequiredError(
        [
          {
            mode: 'url',
            message: 'This tool requires a payment confirmation. Open the link to confirm payment!',
            url: 'https://www.example.com/confirm-payment',
            elicitationId: generateElicitationId(),
          }
        ]
      )
    }
  );

  server.tool(
    'third-party-auth',
    'A tool that requires third-party OAuth credentials',  // description
    {
      param1: z.string().describe('First parameter'),
    },
    async (args, extra): Promise<CallToolResult> => {
      /*
        In a real world scenario, there would be some logic here to check if we already have a valid access token for the user.
        Auth info (with a subject or `sub` claim) can be typically be found in `extra.authInfo`.
        If we do, we can just return the result of the tool call.
        If we don't, we can throw an ElicitationRequiredError to request the user to authenticate.
        For the purposes of this example, we'll just throw an error.

        In this example, we show when the server is able to provide tracking of the elicitation.
        On the server side, we track the elicitationId and return a pending status to the client.
        In a real world scenario, we would update the progress when we recieve a callback from the OAuth provider.
        We would update the progress a final time when we receive a token, indicating to the client that it's safe to retry.
      */
      const sessionId = extra.sessionId;
      if (!sessionId) {
        throw new Error('Expected a Session ID to track elicitation');
      }

      // Create and track the elicitation
      const elicitationId = generateTrackedElicitation(
        sessionId,
        'Third-party authentication required'
      );

      // Simulate OAuth callback after 10 seconds
      // In a real app, this would be called from your OAuth callback handler
      setTimeout(() => {
        console.log(`Simulating OAuth callback for elicitation ${elicitationId}`);
        updateElicitationProgress(elicitationId, 'Received OAuth callback');
      }, 10000);

      // Simulate OAuth token received after 15 seconds
      // In a real app, this would be called from your OAuth callback handler
      setTimeout(() => {
        console.log(`Simulating OAuth token received for elicitation ${elicitationId}`);
        completeElicitation(elicitationId, 'Received OAuth token(s)');
      }, 15000);

      throw new ElicitationRequiredError(
        [
          {
            mode: 'url',
            message: 'This tool requires access to your example.com account. Open the link to authenticate!',
            url: 'https://www.example.com/oauth/authorize',
            elicitationId,
          }
        ]
      )
    }
  );

  // Register a tool that demonstrates elicitation (user input collection)
  // This creates a closure that captures the server instance
  server.tool(
    'collect-user-info',
    'A tool that collects user information through elicitation',
    {
      infoType: z.enum(['contact', 'preferences', 'feedback']).describe('Type of information to collect'),
    },
    async ({ infoType }): Promise<CallToolResult> => {
      let message: string;
      let requestedSchema: {
        type: 'object';
        properties: Record<string, PrimitiveSchemaDefinition>;
        required?: string[];
      };

      switch (infoType) {
        case 'contact':
          message = 'Please provide your contact information';
          requestedSchema = {
            type: 'object',
            properties: {
              name: {
                type: 'string',
                title: 'Full Name',
                description: 'Your full name',
              },
              email: {
                type: 'string',
                title: 'Email Address',
                description: 'Your email address',
                format: 'email',
              },
              phone: {
                type: 'string',
                title: 'Phone Number',
                description: 'Your phone number (optional)',
              },
            },
            required: ['name', 'email'],
          };
          break;
        case 'preferences':
          message = 'Please set your preferences';
          requestedSchema = {
            type: 'object',
            properties: {
              theme: {
                type: 'string',
                title: 'Theme',
                description: 'Choose your preferred theme',
                enum: ['light', 'dark', 'auto'],
                enumNames: ['Light', 'Dark', 'Auto'],
              },
              notifications: {
                type: 'boolean',
                title: 'Enable Notifications',
                description: 'Would you like to receive notifications?',
                default: true,
              },
              frequency: {
                type: 'string',
                title: 'Notification Frequency',
                description: 'How often would you like notifications?',
                enum: ['daily', 'weekly', 'monthly'],
                enumNames: ['Daily', 'Weekly', 'Monthly'],
              },
            },
            required: ['theme'],
          };
          break;
        case 'feedback':
          message = 'Please provide your feedback';
          requestedSchema = {
            type: 'object',
            properties: {
              rating: {
                type: 'integer',
                title: 'Rating',
                description: 'Rate your experience (1-5)',
                minimum: 1,
                maximum: 5,
              },
              comments: {
                type: 'string',
                title: 'Comments',
                description: 'Additional comments (optional)',
                maxLength: 500,
              },
              recommend: {
                type: 'boolean',
                title: 'Would you recommend this?',
                description: 'Would you recommend this to others?',
              },
            },
            required: ['rating', 'recommend'],
          };
          break;
        default:
          throw new Error(`Unknown info type: ${infoType}`);
      }

      try {
        // Use the underlying server instance to elicit input from the client
        const result = await server.server.elicitInput({
          mode: 'form',
          message,
          requestedSchema,
        });

        switch (result.action) {
          case 'accept':
            return {
              content: [
                {
                  type: 'text',
                  text: `Thank you! Collected ${infoType} information: ${JSON.stringify(result.content, null, 2)}`,
                },
              ],
            };
          case 'decline':
            return {
              content: [
                {
                  type: 'text',
                  text: `No information was collected. User declined ${infoType} information request.`,
                },
              ],
            };
          case 'cancel':
            return {
              content: [
                {
                  type: 'text',
                  text: `Information collection was cancelled by the user.`,
                },
              ],
            };
          default:
            throw new Error(`Unknown action: ${result.action}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error collecting ${infoType} information: ${error}`,
            },
          ],
        };
      }
    }
  );

  return server;
};

/**
 * Elicitation Progress Tracking Utilities
 **/

interface ElicitationMetadata {
  status: 'pending' | 'complete';
  progress: number;
  completedPromise: Promise<void>;
  completeResolver: () => void;
  createdAt: Date;
  sessionId: string;
  notificationSender?: (notification: ProgressNotification) => void;
  message: string;
  progressToken?: ProgressToken;
}

const elicitationsMap = new Map<string, ElicitationMetadata>();

// Clean up old elicitations after 1 hour to prevent memory leaks
const ELICITATION_TTL_MS = 60 * 60 * 1000; // 1 hour
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

function cleanupOldElicitations() {
  const now = new Date();
  for (const [id, metadata] of elicitationsMap.entries()) {
    if (now.getTime() - metadata.createdAt.getTime() > ELICITATION_TTL_MS) {
      elicitationsMap.delete(id);
      console.log(`Cleaned up expired elicitation: ${id}`);
    }
  }
}

setInterval(cleanupOldElicitations, CLEANUP_INTERVAL_MS);

/**
 * Elicitation IDs must be unique strings within the MCP session
 * UUIDs are used in this example for simplicity
 */
function generateElicitationId() : string {
  return randomUUID();
}

/**
* Helper function to create and track a new elicitation.
*/
function generateTrackedElicitation(sessionId: string, message?: string): string {
 const elicitationId = generateElicitationId();

 // Create a Promise and its resolver for tracking completion
 let completeResolver: () => void;
 const completedPromise = new Promise<void>((resolve) => {
   completeResolver = resolve;
 });

 // Store the elicitation in our map
 elicitationsMap.set(elicitationId, {
   status: 'pending',
   progress: 0,
   completedPromise,
   completeResolver: completeResolver!,
   createdAt: new Date(),
   sessionId,
   message: message || 'In progress',
 });

 return elicitationId;
}

/**
 * Handler for the elicitation/track request
 */
const trackElicitation: ElicitTrackHandler = async (elicitationId, progressToken, extra) => {
  console.log(`📒 Track elicitation request: ${elicitationId} ${progressToken} (session: ${extra.sessionId})`);

  // Check that the elicitation ID is valid and that the session ID matches
  const elicitationMetadata = elicitationsMap.get(elicitationId);
  if (!elicitationMetadata || elicitationMetadata.sessionId !== extra.sessionId) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Invalid elicitation ID: ${elicitationId}`
    );
  }

  if (elicitationMetadata.status === 'complete') {
    // The elicitation is already complete, so we can return complete
    return {
      status: 'complete',
    };
  }

  // Keep track of the progress token so we can continue to update the client with progress updates
  elicitationMetadata.progressToken = progressToken;
  elicitationMetadata.notificationSender = extra.sendNotification;

  // Send an initial notification to the client with the progress token
  elicitationMetadata.notificationSender({
    method: 'notifications/progress',
    params: {
      progressToken,
      progress: elicitationMetadata.progress,
      message: elicitationMetadata.message,
    },
  });

  // Wait for completion with a timeout
  const TRACK_TIMEOUT_MS = 30 * 1000; // 30 seconds timeout

  try {
    await Promise.race([
      elicitationMetadata.completedPromise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Elicitation tracking timeout')), TRACK_TIMEOUT_MS)
      )
    ]);

    return {
      status: 'complete',
    };
  } catch {
    // Timeout occurred
    // Cleanup progress tracking for this request
    elicitationMetadata.progressToken = undefined;
    elicitationMetadata.notificationSender = undefined;
    throw new McpError(
      ErrorCode.RequestTimeout,
      'Elicitation tracking timed out'
    );
  }
};

/**
 * Helper function to update the progress of an elicitation.
 */
function updateElicitationProgress(elicitationId: string, message?: string) {
  const elicitation = elicitationsMap.get(elicitationId);
  if (!elicitation) {
    console.warn(`Attempted to update unknown elicitation: ${elicitationId}`);
    return;
  }

  if (elicitation.status === 'complete') {
    console.warn(`Elicitation already complete: ${elicitationId}`);
    return;
  }

  if (message) {
    elicitation.message = message;
  }

  elicitation.progress++;

  if (elicitation.progressToken && elicitation.notificationSender) {
    elicitation.notificationSender({
      method: 'notifications/progress',
      params: {
        progressToken: elicitation.progressToken,
        progress: elicitation.progress,
        message: elicitation.message,
      },
    });
  }
}

/**
 * Helper function to complete an elicitation.
 */
function completeElicitation(elicitationId: string, message?: string) {
  const elicitation = elicitationsMap.get(elicitationId);
  if (!elicitation) {
    console.warn(`Attempted to complete unknown elicitation: ${elicitationId}`);
    return;
  }

  if (elicitation.status === 'complete') {
    console.warn(`Elicitation already complete: ${elicitationId}`);
    return;
  }

  // Update metadata
  elicitation.status = 'complete';
  elicitation.message = message || 'Complete';
  elicitation.progress++;

  // Send a final notification to the client with the progress token
  if (elicitation.progressToken && elicitation.notificationSender) {
    elicitation.notificationSender({
      method: 'notifications/progress',
      params: {
        progressToken: elicitation.progressToken,
        progress: elicitation.progress,
        total: elicitation.progress,
        message: elicitation.message,
      },
    });
  }

  // Resolve the promise to unblock the request handler
  elicitation.completeResolver();
}

const MCP_PORT = process.env.MCP_PORT ? parseInt(process.env.MCP_PORT, 10) : 3000;
const AUTH_PORT = process.env.MCP_AUTH_PORT ? parseInt(process.env.MCP_AUTH_PORT, 10) : 3001;

const app = express();
app.use(express.json());

// Allow CORS all domains, expose the Mcp-Session-Id header
app.use(cors({
  origin: '*', // Allow all origins
  exposedHeaders: ["Mcp-Session-Id"],
  credentials: true // Allow cookies to be sent cross-origin
}));

// Set up OAuth if enabled
let authMiddleware = null;
if (useOAuth) {
  // Create auth middleware for MCP endpoints
  const mcpServerUrl = new URL(`http://localhost:${MCP_PORT}/mcp`);
  const authServerUrl = new URL(`http://localhost:${AUTH_PORT}`);

  const oauthMetadata: OAuthMetadata = setupAuthServer({ authServerUrl, mcpServerUrl, strictResource: strictOAuth });

  const tokenVerifier = {
    verifyAccessToken: async (token: string) => {
      const endpoint = oauthMetadata.introspection_endpoint;

      if (!endpoint) {
        throw new Error('No token verification endpoint available in metadata');
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          token: token
        }).toString()
      });


      if (!response.ok) {
        throw new Error(`Invalid or expired token: ${await response.text()}`);
      }

      const data = await response.json();

      if (strictOAuth) {
        if (!data.aud) {
          throw new Error(`Resource Indicator (RFC8707) missing`);
        }
        if (!checkResourceAllowed({ requestedResource: data.aud, configuredResource: mcpServerUrl })) {
          throw new Error(`Expected resource indicator ${mcpServerUrl}, got: ${data.aud}`);
        }
      }

      // Convert the response to AuthInfo format
      return {
        token,
        clientId: data.client_id,
        scopes: data.scope ? data.scope.split(' ') : [],
        expiresAt: data.exp,
      };
    }
  }
  // Add metadata routes to the main MCP server
  app.use(mcpAuthMetadataRouter({
    oauthMetadata,
    resourceServerUrl: mcpServerUrl,
    scopesSupported: ['mcp:tools'],
    resourceName: 'MCP Demo Server',
  }));

  authMiddleware = requireBearerAuth({
    verifier: tokenVerifier,
    requiredScopes: [],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
  });
}

/**
 * API Key Form Handling
 *
 * Many servers today require an API key to operate, but there's no scalable way to do this dynamically for remote servers within MCP protocol.
 * URL-mode elicitation enables the server to host a simple form and get the secret data securely from the user without involving the LLM or client.
 **/

// Interface for a function that can send an elicitation request
type ElicitationSender = (params: ElicitRequestURLParams) => Promise<ElicitResult>;

async function sendApiKeyElicitation(sessionId: string, sender: ElicitationSender) {
  if (!sessionId) {
    console.error('No session ID provided');
    throw new Error('Expected a Session ID to track elicitation');
  }

  console.log('🔑 Requesting API key from client...');
  const elicitationId = generateTrackedElicitation(sessionId);
  try {
    const result = await sender({
      mode: 'url',
      message: 'Please provide your API key to authenticate with this server',
      // Host the form on the same server. In a real app, you might coordinate passing these state variables differently.
      url: `http://localhost:${MCP_PORT}/api-key-form?session=${sessionId}&elicitation=${elicitationId}`,
      elicitationId,
    });

    switch (result.action) {
      case 'accept':
        console.log('API key elicitation accepted by client');
        // Wait for the API key to be submitted via the form
        // The form submission will complete the elicitation
        break;
      default:
        console.log('API key not provided by client');
        // In a real app, this might close the connection, but for the demo, we'll continue
        break;
    }
  } catch (error) {
    console.error('Error during API key elicitation:', error);
  }
}

// API Key Form endpoint - serves a simple HTML form
app.get('/api-key-form', (req: Request, res: Response) => {
  const mcpSessionId = req.query.session as string | undefined;
  const elicitationId = req.query.elicitation as string | undefined;
  if (!mcpSessionId || !elicitationId) {
    res.status(400).send('<h1>Error</h1><p>Missing required parameters</p>');
    return;
  }

  // Check for user session cookie
  // In production, this is often handled by some user auth middleware to ensure the user has a valid session
  // This session is different from the MCP session.
  // This userSession is the cookie that the MCP Server's Authorization Server sets for the user when they log in.
  const userSession = getUserSessionCookie(req.headers.cookie);
  if (!userSession) {
    res.status(401).send('<h1>Error</h1><p>Unauthorized - please reconnect to login again</p>');
    return;
  }

  updateElicitationProgress(elicitationId, 'Waiting for you to submit your API key...');

  // Serve a simple HTML form
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Submit Your API Key</title>
      <style>
        body { font-family: sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        input[type="text"] { width: 100%; padding: 8px; margin: 10px 0; box-sizing: border-box; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .user { background: #d1ecf1; padding: 8px; margin-bottom: 10px; }
        .info { color: #666; font-size: 0.9em; margin-top: 20px; }
      </style>
    </head>
    <body>
      <h1>API Key Required</h1>
      <div class="user">✓ Logged in as: <strong>${userSession.name}</strong></div>
      <form method="POST" action="/api-key-form">
        <input type="hidden" name="session" value="${mcpSessionId}" />
        <input type="hidden" name="elicitation" value="${elicitationId}" />
        <label>API Key:<br>
          <input type="text" name="apiKey" required placeholder="Enter your API key" />
        </label>
        <button type="submit">Submit</button>
      </form>
      <div class="info">This is a demo showing how a server can elicit sensitive data from a user.</div>
    </body>
    </html>
  `);
});

// Handle API key form submission
app.post('/api-key-form', express.urlencoded(), (req: Request, res: Response) => {
  const { session: sessionId, apiKey, elicitation: elicitationId } = req.body;
  if (!sessionId || !apiKey || !elicitationId) {
    res.status(400).send('<h1>Error</h1><p>Missing required parameters</p>');
    return;
  }

  // Check for user session cookie here too
  const userSession = getUserSessionCookie(req.headers.cookie);
  if (!userSession) {
    res.status(401).send('<h1>Error</h1><p>Unauthorized - please reconnect to login again</p>');
    return;
  }

  // A real app might store this API key to be used later for the user.
  console.log(`🔑 Received API key \x1b[32m${apiKey}\x1b[0m for session ${sessionId}`);

  // If we have an elicitationId, complete the elicitation
  completeElicitation(elicitationId, 'API key received');

  // Send a success response
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Success</title>
      <style>
        body { font-family: sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; text-align: center; }
        .success { background: #d4edda; color: #155724; padding: 20px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="success">
        <h1>Success ✓</h1>
        <p>API key received.</p>
      </div>
      <p>You can close this window and return to your MCP client.</p>
    </body>
    </html>
  `);
});

// Helper to get the user session from the demo_session cookie
function getUserSessionCookie(cookieHeader?: string): { userId: string; name: string; timestamp: number } | null {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'demo_session' && value) {
      try {
        return JSON.parse(decodeURIComponent(value));
      } catch (error) {
        console.error('Failed to parse demo_session cookie:', error);
        return null;
      }
    }
  }
  return null;
}

// Map to store transports by session ID
const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

// Track sessions that need an elicitation request to be sent
const sessionsNeedingElicitation: { [sessionId: string]: ElicitationSender } = {};

// MCP POST endpoint with optional auth
const mcpPostHandler = async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (sessionId) {
    console.log(`Received MCP request for session: ${sessionId}`);
  } else {
    console.log('Request body:', req.body);
  }

  if (useOAuth && req.auth) {
    console.log('Authenticated user:', req.auth);
  }
  try {
    let transport: StreamableHTTPServerTransport;
    if (sessionId && transports[sessionId]) {
      // Reuse existing transport
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      const server = getServer();
      // New initialization request
      const eventStore = new InMemoryEventStore();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        eventStore, // Enable resumability
        onsessioninitialized: (sessionId) => {
          // Store the transport by session ID when session is initialized
          // This avoids race conditions where requests might come in before the session is stored
          console.log(`Session initialized with ID: ${sessionId}`);
          transports[sessionId] = transport;
          sessionsNeedingElicitation[sessionId] = server.server.elicitInput.bind(server.server);
        },
      });

      // Set up onclose handler to clean up transport when closed
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid && transports[sid]) {
          console.log(`Transport closed for session ${sid}, removing from transports map`);
          delete transports[sid];
          delete sessionsNeedingElicitation[sid];
        }
      };

      // Connect the transport to the MCP server BEFORE handling the request
      // so responses can flow back through the same transport
      await server.connect(transport);

      await transport.handleRequest(req, res, req.body);
      return; // Already handled
    } else {
      // Invalid request - no session ID or not initialization request
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Bad Request: No valid session ID provided',
        },
        id: null,
      });
      return;
    }

    // Handle the request with existing transport - no need to reconnect
    // The existing transport is already connected to the server
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error('Error handling MCP request:', error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32603,
          message: 'Internal server error',
        },
        id: null,
      });
    }
  }
};

// Set up routes with conditional auth middleware
if (useOAuth && authMiddleware) {
  app.post('/mcp', authMiddleware, mcpPostHandler);
} else {
  app.post('/mcp', mcpPostHandler);
}

// Handle GET requests for SSE streams (using built-in support from StreamableHTTP)
const mcpGetHandler = async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  if (useOAuth && req.auth) {
    console.log('Authenticated SSE connection from user:', req.auth);
  }

  // Check for Last-Event-ID header for resumability
  const lastEventId = req.headers['last-event-id'] as string | undefined;
  if (lastEventId) {
    console.log(`Client reconnecting with Last-Event-ID: ${lastEventId}`);
  } else {
    console.log(`Establishing new SSE stream for session ${sessionId}`);
  }

  const transport = transports[sessionId];
  await transport.handleRequest(req, res);

  if (sessionsNeedingElicitation[sessionId]) {
    const elicitationSender = sessionsNeedingElicitation[sessionId];

    // Send an elicitation request to the client in the background
    sendApiKeyElicitation(sessionId, elicitationSender)
      .then(() => {
        // Only delete on successful send for this demo
        delete sessionsNeedingElicitation[sessionId];
        console.log(`Successfully sent API key elicitation for session ${sessionId}`);
      })
      .catch(error => {
        console.error('Error sending API key elicitation:', error);
        // Keep in map to potentially retry on next reconnect
      });
  }
};

// Set up GET route with conditional auth middleware
if (useOAuth && authMiddleware) {
  app.get('/mcp', authMiddleware, mcpGetHandler);
} else {
  app.get('/mcp', mcpGetHandler);
}

// Handle DELETE requests for session termination (according to MCP spec)
const mcpDeleteHandler = async (req: Request, res: Response) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports[sessionId]) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }

  console.log(`Received session termination request for session ${sessionId}`);

  try {
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
  } catch (error) {
    console.error('Error handling session termination:', error);
    if (!res.headersSent) {
      res.status(500).send('Error processing session termination');
    }
  }
};

// Set up DELETE route with conditional auth middleware
if (useOAuth && authMiddleware) {
  app.delete('/mcp', authMiddleware, mcpDeleteHandler);
} else {
  app.delete('/mcp', mcpDeleteHandler);
}

app.listen(MCP_PORT, (error) => {
  if (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
  console.log(`MCP Streamable HTTP Server listening on port ${MCP_PORT}`);
});

// Handle server shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down server...');

  // Close all active transports to properly clean up resources
  for (const sessionId in transports) {
    try {
      console.log(`Closing transport for session ${sessionId}`);
      await transports[sessionId].close();
      delete transports[sessionId];
      delete sessionsNeedingElicitation[sessionId];
    } catch (error) {
      console.error(`Error closing transport for session ${sessionId}:`, error);
    }
  }
  console.log('Server shutdown complete');
  process.exit(0);
});
