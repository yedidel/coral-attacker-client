import axios, { AxiosInstance } from 'axios';
// @ts-ignore
import { EventSource } from 'eventsource';
import * as dotenv from 'dotenv';

dotenv.config();


const PROXY_URL = "http://localhost:8888"; 
const REAL_SERVER_URL = "http://localhost:9000";

const APP_ID = "test-app";
const PRIVACY_KEY = "test-key";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const AGENT_NAME_IN_SESSION = "test-agent";


const realApiClient: AxiosInstance = axios.create({ baseURL: REAL_SERVER_URL, timeout: 5000 });
const SESSION_CREATION_PAYLOAD = {
    "applicationId": APP_ID, "privacyKey": PRIVACY_KEY,
    "agentGraphRequest": { "agents": [{
        "id": { "name": "interface", "version": "0.0.1" },
        "name": AGENT_NAME_IN_SESSION, "description": "MITM Test Listener",
        "options": { "OPENAI_API_KEY": { "type": "string", "value": OPENAI_API_KEY }},
        "systemPrompt": null, "blocking": false, "customToolAccess": [],
        "coralPlugins": [], "provider": { "type": "local", "runtime": "executable" }
    }], "groups": [], "customTools": {} }
};

async function createValidSession(): Promise<string | null> {
    console.log(`[Listener] Creating session against real server at ${REAL_SERVER_URL}...`);
    try {
        const response = await realApiClient.post('/api/v1/sessions', SESSION_CREATION_PAYLOAD);
        if (response.status === 200 && response.data.sessionId) {
            console.log(`[Listener] Session created: ${response.data.sessionId}`);
            return response.data.sessionId;
        }
        console.error(`[Listener] Error creating session (Status ${response.status})`);
        return null;
    } catch (error: any) {
        console.error(`[Listener] Error creating session: ${error.message}`);
        return null;
    }
}

// Helper function to send the POST
async function sendTriggerPost(sessionId: string, transportId: string) {
    try {
        console.log(`[Listener] Sending 'trigger' POST with Transport ID: ${transportId}`);
        const proxyApiClient: AxiosInstance = axios.create({ baseURL: PROXY_URL, timeout: 5000 });
        
        // --- Critical fix ---
        // Using the transportId we obtained
        const messageUrl = `/api/v1/message/${APP_ID}/${PRIVACY_KEY}/${sessionId}?transportId=${transportId}`;
        
        const response = await proxyApiClient.post(messageUrl, {
            "content": "Hello agent, this is a test message *with ID*. Please respond.",
            "sender": "mitm-test-user-valid"
        });
        
        console.log(`✅ [Listener] 'Trigger' POST message sent successfully! Server response: ${response.status}`);
    } catch (error: any) {
        console.error(`[Listener] Error sending 'trigger' POST message (even with ID): ${error.message}`);
    }
}

// --- Main experiment function (correct version) ---
async function runMitmTest() {
    if (!OPENAI_API_KEY) {
        console.error("❌ ERROR: OPENAI_API_KEY is not set.");
        return;
    }

    const sessionId = await createValidSession();
    if (!sessionId) return;

    // --- Critical fix ---
    // We create a Promise that doesn't close, so the script
    // continues to run and listen for events.
    await new Promise<void>(async (resolve, reject) => {
        const sseUrl = `${PROXY_URL}/sse/v1/${APP_ID}/${PRIVACY_KEY}/${sessionId}/sse?agentId=${AGENT_NAME_IN_SESSION}`;
        console.log(`[Listener] Connecting to SSE through proxy: ${sseUrl}`);
        
        const es = new EventSource(sseUrl);

        let capturedTransportId: any = null;
        let postSent = false; // Ensure we send the POST only once

        es.onopen = () => {
            console.log("✅ [Listener] SSE connection opened.");
        };

        es.addEventListener('message', async (event: any) => {
            console.log("\n-------------------------------------------------");
            console.log("🔥 [Listener] Received SSE message from server:");
            console.log(`Raw Data: ${event.data}`);
            console.log("-------------------------------------------------\n");

            try {
                const data = JSON.parse(event.data);
                
                // Assume the key is 'transportId'. Change if needed
                // This is the key we found in your article (section 8.3.1)
                if (data.transportId && !postSent) { 
                    postSent = true; // Mark as sent
                    capturedTransportId = data.transportId;
                    console.log(`✅ [Listener] Captured Transport ID: ${capturedTransportId}`);
                    
                    // --- Now we send the POST ---
                    await sendTriggerPost(sessionId, capturedTransportId);
                } else if (data.content) {
                    console.log("[Listener] This is a regular content message (agent response).");
                }

            } catch (e) {
                console.log("[Listener] Received SSE message is not JSON.");
            }
        });

        es.onerror = (err: any) => {
            // If connection fails, finish the Promise with an error
            console.error("❌ [Listener] Critical SSE error:", err.message || 'Error');
            reject(new Error("SSE Connection Failed"));
        };

        // We never call resolve() so the script continues to listen
    });
}

runMitmTest().catch(console.error);