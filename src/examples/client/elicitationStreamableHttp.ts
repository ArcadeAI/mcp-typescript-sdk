import { Client } from '../../client/index.js';
import { StreamableHTTPClientTransport } from '../../client/streamableHttp.js';
import { createInterface } from 'node:readline';
import {
  ListToolsRequest,
  ListToolsResultSchema,
  CallToolRequest,
  CallToolResultSchema,
  ElicitRequestSchema,
  ElicitRequest,
  ElicitResult,
  ResourceLink,
} from '../../types.js';
import { getDisplayName } from '../../shared/metadataUtils.js';
import Ajv from "ajv";
import { OAuthClientMetadata } from 'src/shared/auth.js';
import { exec } from 'node:child_process';
import { InMemoryOAuthClientProvider } from './simpleOAuthClientProvider.js';
import { UnauthorizedError } from 'src/client/auth.js';
import { createServer } from 'node:http';

// Check for OAuth flag
const useOAuth = process.argv.includes('--oauth');
const OAUTH_CALLBACK_PORT = 8090; // Use different port than auth server (3001)
const OAUTH_CALLBACK_URL = `http://localhost:${OAUTH_CALLBACK_PORT}/callback`;
let oauthProvider: InMemoryOAuthClientProvider | undefined = undefined;
if (useOAuth) {
  console.log('Getting OAuth token...');
  const clientMetadata: OAuthClientMetadata = {
    client_name: 'Elicitation MCP Client',
    redirect_uris: [OAUTH_CALLBACK_URL],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
    scope: 'mcp:tools'
  };
  oauthProvider = new InMemoryOAuthClientProvider(
    OAUTH_CALLBACK_URL,
    clientMetadata,
    (redirectUrl: URL) => {
      console.log(`📌 OAuth redirect handler called - opening browser`);
      console.log(`Opening browser to: ${redirectUrl.toString()}`);
      openBrowser(redirectUrl.toString());
    }
  );
}

// Create readline interface for user input
const readline = createInterface({
  input: process.stdin,
  output: process.stdout
});

// Global client and transport for interactive commands
let client: Client | null = null;
let transport: StreamableHTTPClientTransport | null = null;
let serverUrl = 'http://localhost:3000/mcp';
let sessionId: string | undefined = undefined;

async function main(): Promise<void> {
  console.log('MCP Interactive Client');
  console.log('=====================');

  // Connect to server immediately with default settings
  await connect();

  // Print help and start the command loop
  printHelp();
  commandLoop();
}

function printHelp(): void {
  console.log('\nAvailable commands:');
  console.log('  connect [url]              - Connect to MCP server (default: http://localhost:3000/mcp)');
  console.log('  disconnect                 - Disconnect from server');
  console.log('  terminate-session          - Terminate the current session');
  console.log('  reconnect                  - Reconnect to the server');
  console.log('  list-tools                 - List available tools');
  console.log('  call-tool <name> [args]    - Call a tool with optional JSON arguments');
  console.log('  collect-info [type]        - Test elicitation with collect-user-info tool (contact/preferences/feedback)');
  console.log('  help                       - Show this help');
  console.log('  quit                       - Exit the program');
}

function commandLoop(): void {
  readline.question('\n> ', async (input) => {
    const args = input.trim().split(/\s+/);
    const command = args[0]?.toLowerCase();

    try {
      switch (command) {
        case 'connect':
          await connect(args[1]);
          break;

        case 'disconnect':
          await disconnect();
          break;

        case 'terminate-session':
          await terminateSession();
          break;

        case 'reconnect':
          await reconnect();
          break;

        case 'list-tools':
          await listTools();
          break;

        case 'call-tool':
          if (args.length < 2) {
            console.log('Usage: call-tool <name> [args]');
          } else {
            const toolName = args[1];
            let toolArgs = {};
            if (args.length > 2) {
              try {
                toolArgs = JSON.parse(args.slice(2).join(' '));
              } catch {
                console.log('Invalid JSON arguments. Using empty args.');
              }
            }
            await callTool(toolName, toolArgs);
          }
          break;

        case 'collect-info':
          await callCollectInfoTool(args[1] || 'contact');
          break;

        case 'help':
          printHelp();
          break;

        case 'quit':
        case 'exit':
          await cleanup();
          return;

        default:
          if (command) {
            console.log(`Unknown command: ${command}`);
          }
          break;
      }
    } catch (error) {
      console.error(`Error executing command: ${error}`);
    }

    // Continue the command loop
    commandLoop();
  });
}

async function openBrowser(url: string): Promise<void> {
  console.log(`🌐 Opening browser for authorization: ${url}`);

  const command = `open "${url}"`;

  exec(command, (error) => {
    if (error) {
      console.error(`Failed to open browser: ${error.message}`);
      console.log(`Please manually open: ${url}`);
    }
  });
}

async function handleElicitationRequest(request: ElicitRequest): Promise<ElicitResult> {
  console.log('\n🔔 Elicitation Request Received:');
  console.log(`Message: ${request.params.message}`);
  console.log('Requested Schema:');
  console.log(JSON.stringify(request.params.requestedSchema, null, 2));

  const schema = request.params.requestedSchema;
  const properties = schema.properties;
  const required = schema.required || [];

  // Set up AJV validator for the requested schema
  const ajv = new Ajv();
  const validate = ajv.compile(schema);

  let attempts = 0;
  const maxAttempts = 3;

  while (attempts < maxAttempts) {
    attempts++;
    console.log(`\nPlease provide the following information (attempt ${attempts}/${maxAttempts}):`);

    const content: Record<string, unknown> = {};
    let inputCancelled = false;

    // Collect input for each field
    for (const [fieldName, fieldSchema] of Object.entries(properties)) {
      const field = fieldSchema as {
        type?: string;
        title?: string;
        description?: string;
        default?: unknown;
        enum?: string[];
        minimum?: number;
        maximum?: number;
        minLength?: number;
        maxLength?: number;
        format?: string;
      };

      const isRequired = required.includes(fieldName);
      let prompt = `${field.title || fieldName}`;

      // Add helpful information to the prompt
      if (field.description) {
        prompt += ` (${field.description})`;
      }
      if (field.enum) {
        prompt += ` [options: ${field.enum.join(', ')}]`;
      }
      if (field.type === 'number' || field.type === 'integer') {
        if (field.minimum !== undefined && field.maximum !== undefined) {
          prompt += ` [${field.minimum}-${field.maximum}]`;
        } else if (field.minimum !== undefined) {
          prompt += ` [min: ${field.minimum}]`;
        } else if (field.maximum !== undefined) {
          prompt += ` [max: ${field.maximum}]`;
        }
      }
      if (field.type === 'string' && field.format) {
        prompt += ` [format: ${field.format}]`;
      }
      if (isRequired) {
        prompt += ' *required*';
      }
      if (field.default !== undefined) {
        prompt += ` [default: ${field.default}]`;
      }

      prompt += ': ';

      const answer = await new Promise<string>((resolve) => {
        readline.question(prompt, (input) => {
          resolve(input.trim());
        });
      });

      // Check for cancellation
      if (answer.toLowerCase() === 'cancel' || answer.toLowerCase() === 'c') {
        inputCancelled = true;
        break;
      }

      // Parse and validate the input
      try {
        if (answer === '' && field.default !== undefined) {
          content[fieldName] = field.default;
        } else if (answer === '' && !isRequired) {
          // Skip optional empty fields
          continue;
        } else if (answer === '') {
          throw new Error(`${fieldName} is required`);
        } else {
          // Parse the value based on type
          let parsedValue: unknown;

          if (field.type === 'boolean') {
            parsedValue = answer.toLowerCase() === 'true' || answer.toLowerCase() === 'yes' || answer === '1';
          } else if (field.type === 'number') {
            parsedValue = parseFloat(answer);
            if (isNaN(parsedValue as number)) {
              throw new Error(`${fieldName} must be a valid number`);
            }
          } else if (field.type === 'integer') {
            parsedValue = parseInt(answer, 10);
            if (isNaN(parsedValue as number)) {
              throw new Error(`${fieldName} must be a valid integer`);
            }
          } else if (field.enum) {
            if (!field.enum.includes(answer)) {
              throw new Error(`${fieldName} must be one of: ${field.enum.join(', ')}`);
            }
            parsedValue = answer;
          } else {
            parsedValue = answer;
          }

          content[fieldName] = parsedValue;
        }
      } catch (error) {
        console.log(`❌ Error: ${error}`);
        // Continue to next attempt
        break;
      }
    }

    if (inputCancelled) {
      return { action: 'cancel' };
    }

    // If we didn't complete all fields due to an error, try again
    if (Object.keys(content).length !== Object.keys(properties).filter(name =>
      required.includes(name) || content[name] !== undefined
    ).length) {
      if (attempts < maxAttempts) {
        console.log('Please try again...');
        continue;
      } else {
        console.log('Maximum attempts reached. Declining request.');
        return { action: 'decline' };
      }
    }

    // Validate the complete object against the schema
    const isValid = validate(content);

    if (!isValid) {
      console.log('❌ Validation errors:');
      validate.errors?.forEach(error => {
        console.log(`  - ${error.dataPath || 'root'}: ${error.message}`);
      });

      if (attempts < maxAttempts) {
        console.log('Please correct the errors and try again...');
        continue;
      } else {
        console.log('Maximum attempts reached. Declining request.');
        return { action: 'decline' };
      }
    }

    // Show the collected data and ask for confirmation
    console.log('\n✅ Collected data:');
    console.log(JSON.stringify(content, null, 2));

    const confirmAnswer = await new Promise<string>((resolve) => {
      readline.question('\nSubmit this information? (yes/no/cancel): ', (input) => {
        resolve(input.trim().toLowerCase());
      });
    });


    if (confirmAnswer === 'yes' || confirmAnswer === 'y') {
      return {
        action: 'accept',
        content,
      };
    } else if (confirmAnswer === 'cancel' || confirmAnswer === 'c') {
      return { action: 'cancel' };
    } else if (confirmAnswer === 'no' || confirmAnswer === 'n') {
      if (attempts < maxAttempts) {
        console.log('Please re-enter the information...');
        continue;
      } else {
        return { action: 'decline' };
      }
    }
  }

  console.log('Maximum attempts reached. Declining request.');
  return { action: 'decline' };
}
/**
 * Example OAuth callback handler - in production, use a more robust approach
 * for handling callbacks and storing tokens
 */
/**
 * Starts a temporary HTTP server to receive the OAuth callback
 */
async function waitForOAuthCallback(): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const server = createServer((req, res) => {
      // Ignore favicon requests
      if (req.url === '/favicon.ico') {
        res.writeHead(404);
        res.end();
        return;
      }

      console.log(`📥 Received callback: ${req.url}`);
      const parsedUrl = new URL(req.url || '', 'http://localhost');
      const code = parsedUrl.searchParams.get('code');
      const error = parsedUrl.searchParams.get('error');

      if (code) {
        console.log(`✅ Authorization code received: ${code?.substring(0, 10)}...`);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
          <html>
            <body>
              <h1>Authorization Successful!</h1>
              <p>This simulates successful authorization of the MCP client, which now has an access token for the MCP server.</p>
              <p>This window will close automatically in 10 seconds.</p>
              <script>setTimeout(() => window.close(), 10000);</script>
            </body>
          </html>
        `);

        resolve(code);
        setTimeout(() => server.close(), 15000);
      } else if (error) {
        console.log(`❌ Authorization error: ${error}`);
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`
          <html>
            <body>
              <h1>Authorization Failed</h1>
              <p>Error: ${error}</p>
            </body>
          </html>
        `);
        reject(new Error(`OAuth authorization failed: ${error}`));
      } else {
        console.log(`❌ No authorization code or error in callback`);
        res.writeHead(400);
        res.end('Bad request');
        reject(new Error('No authorization code provided'));
      }
    });

    server.listen(OAUTH_CALLBACK_PORT, () => {
      console.log(`OAuth callback server started on http://localhost:${OAUTH_CALLBACK_PORT}`);
    });
  });
}

async function connect(url?: string): Promise<void> {
  if (client) {
    console.log('Already connected. Disconnect first.');
    return;
  }

  if (url) {
    serverUrl = url;
  }

  // Create a new client with elicitation capability
  client = new Client({
    name: 'example-client',
    version: '1.0.0'
  }, {
    capabilities: {
      elicitation: {},
    },
  });
  if (!transport) { // Only create a new transport if one doesn't exist
    transport = new StreamableHTTPClientTransport(
      new URL(serverUrl),
      {
        sessionId: sessionId,
        authProvider: oauthProvider
      }
    );
  }

  // Set up elicitation request handler with proper validation
  client.setRequestHandler(ElicitRequestSchema, handleElicitationRequest);

  try {
    console.log(`Connecting to ${serverUrl}...`);
    // Connect the client
    await client.connect(transport);
    sessionId = transport.sessionId
    console.log('Transport created with session ID:', sessionId);
    console.log('Connected to MCP server');
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      console.log('OAuth required - waiting for authorization...');
      const callbackPromise = waitForOAuthCallback();
      const authCode = await callbackPromise;
      await transport.finishAuth(authCode);
      console.log('🔐 Authorization code received:', authCode);
      console.log('🔌 Reconnecting with authenticated transport...');
      transport = new StreamableHTTPClientTransport(
        new URL(serverUrl),
        {
          sessionId: sessionId,
          authProvider: oauthProvider
        }
      );
      await client.connect(transport);
    } else {
      console.error('Failed to connect:', error);
      client = null;
      transport = null;
      return;
    }
  }
  // Set up error handler after connection is established so we don't double log errors
  client.onerror = (error) => {
    console.error('\x1b[31mClient error:', error, '\x1b[0m');
  }
}

async function disconnect(): Promise<void> {
  if (!client || !transport) {
    console.log('Not connected.');
    return;
  }

  try {
    await transport.close();
    console.log('Disconnected from MCP server');
    client = null;
    transport = null;
  } catch (error) {
    console.error('Error disconnecting:', error);
  }
}

async function terminateSession(): Promise<void> {
  if (!client || !transport) {
    console.log('Not connected.');
    return;
  }

  try {
    console.log('Terminating session with ID:', transport.sessionId);
    await transport.terminateSession();
    console.log('Session terminated successfully');

    // Check if sessionId was cleared after termination
    if (!transport.sessionId) {
      console.log('Session ID has been cleared');
      sessionId = undefined;

      // Also close the transport and clear client objects
      await transport.close();
      console.log('Transport closed after session termination');
      client = null;
      transport = null;
    } else {
      console.log('Server responded with 405 Method Not Allowed (session termination not supported)');
      console.log('Session ID is still active:', transport.sessionId);
    }
  } catch (error) {
    console.error('Error terminating session:', error);
  }
}

async function reconnect(): Promise<void> {
  if (client) {
    await disconnect();
  }
  await connect();
}

async function listTools(): Promise<void> {
  if (!client) {
    console.log('Not connected to server.');
    return;
  }

  try {
    const toolsRequest: ListToolsRequest = {
      method: 'tools/list',
      params: {}
    };
    const toolsResult = await client.request(toolsRequest, ListToolsResultSchema);

    console.log('Available tools:');
    if (toolsResult.tools.length === 0) {
      console.log('  No tools available');
    } else {
      for (const tool of toolsResult.tools) {
        console.log(`  - id: ${tool.name}, name: ${getDisplayName(tool)}, description: ${tool.description}`);
      }
    }
  } catch (error) {
    console.log(`Tools not supported by this server (${error})`);
  }
}

async function callTool(name: string, args: Record<string, unknown>): Promise<void> {
  if (!client) {
    console.log('Not connected to server.');
    return;
  }

  try {
    const request: CallToolRequest = {
      method: 'tools/call',
      params: {
        name,
        arguments: args
      }
    };

    console.log(`Calling tool '${name}' with args:`, args);
    const result = await client.request(request, CallToolResultSchema);

    console.log('Tool result:');
    const resourceLinks: ResourceLink[] = [];

    result.content.forEach(item => {
      if (item.type === 'text') {
        console.log(`  ${item.text}`);
      } else if (item.type === 'resource_link') {
        const resourceLink = item as ResourceLink;
        resourceLinks.push(resourceLink);
        console.log(`  📁 Resource Link: ${resourceLink.name}`);
        console.log(`     URI: ${resourceLink.uri}`);
        if (resourceLink.mimeType) {
          console.log(`     Type: ${resourceLink.mimeType}`);
        }
        if (resourceLink.description) {
          console.log(`     Description: ${resourceLink.description}`);
        }
      } else if (item.type === 'resource') {
        console.log(`  [Embedded Resource: ${item.resource.uri}]`);
      } else if (item.type === 'image') {
        console.log(`  [Image: ${item.mimeType}]`);
      } else if (item.type === 'audio') {
        console.log(`  [Audio: ${item.mimeType}]`);
      } else {
        console.log(`  [Unknown content type]:`, item);
      }
    });

    // Offer to read resource links
    if (resourceLinks.length > 0) {
      console.log(`\nFound ${resourceLinks.length} resource link(s). Use 'read-resource <uri>' to read their content.`);
    }
  } catch (error) {
    console.log(`Error calling tool ${name}: ${error}`);
  }
}

async function callCollectInfoTool(infoType: string): Promise<void> {
  console.log(`Testing elicitation with collect-user-info tool (${infoType})...`);
  await callTool('collect-user-info', { infoType });
}

async function cleanup(): Promise<void> {
  if (client && transport) {
    try {
      // First try to terminate the session gracefully
      if (transport.sessionId) {
        try {
          console.log('Terminating session before exit...');
          await transport.terminateSession();
          console.log('Session terminated successfully');
        } catch (error) {
          console.error('Error terminating session:', error);
        }
      }

      // Then close the transport
      await transport.close();
    } catch (error) {
      console.error('Error closing transport:', error);
    }
  }

  process.stdin.setRawMode(false);
  readline.close();
  console.log('\nGoodbye!');
  process.exit(0);
}

// Set up raw mode for keyboard input to capture Escape key
process.stdin.setRawMode(true);
process.stdin.on('data', async (data) => {
  // Check for Escape key (27)
  if (data.length === 1 && data[0] === 27) {
    console.log('\nESC key pressed. Disconnecting from server...');

    // Abort current operation and disconnect from server
    if (client && transport) {
      await disconnect();
      console.log('Disconnected. Press Enter to continue.');
    } else {
      console.log('Not connected to server.');
    }

    // Re-display the prompt
    process.stdout.write('> ');
  }
});

// Handle Ctrl+C
process.on('SIGINT', async () => {
  console.log('\nReceived SIGINT. Cleaning up...');
  await cleanup();
});

// Start the interactive client
main().catch((error: unknown) => {
  console.error('Error running MCP client:', error);
  process.exit(1);
});
