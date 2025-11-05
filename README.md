# Coral Adversarial Client

This project contains an adversarial testing client for the Coral protocol server implementation. It tests various security aspects of the server by simulating different types of attacks.

## Experiment Overview

The adversarial client performs a series of security tests against a Coral server instance to evaluate its resilience against various attack vectors:

1. Data Tampering Attack
2. Replay Attack
3. Spoofing Attack (SSE)
4. Prompt Injection Attack
5. SCA Impersonation Attack (SSE)
6. PII Leakage Attack
7. Registry Pollution Attack
8. Leak Exposure Attack
9. Compliance Gaps Attack

## Prerequisites

- Node.js (version 18 or higher)
- npm (usually comes with Node.js)
- A running instance of the Coral server
- An OpenAI API key

## Installation

1. Clone the repository (if not already cloned):
   ```
   git clone <repository-url>
   cd coral-attacker-client
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the project root with your OpenAI API key:
   ```
   OPENAI_API_KEY=your_actual_openai_api_key_here
   ```

## Configuration

Before running the tests, you may want to adjust some settings in the [adversarial_client.ts]
file:

- `BASE_URL`: The URL of the Coral server (default: http://localhost:9000)
- `APP_ID`: Application identifier for the tests
- `PRIVACY_KEY`: Privacy key for the tests
- `NUM_TRIALS`: Number of trials for each attack (default: 50)

## Running the Tests

Compile the TypeScript code:
```
npx tsc
```

Run the adversarial client:
```
node adversarial_client.js
```

Or run directly with ts-node:
```
npx ts-node adversarial_client.ts
```

## Test Results

The client will output results in the console showing:
- Defense success rate for each attack type
- Average latency for each attack
- Average impact score
- Overall defense statistics

## Interpreting Results

- **Defense Success Rate**: Higher percentage indicates better protection
- **Impact Score**: Lower score indicates less potential damage (0.0 = no impact, 1.0 = full impact)
- **Latency**: Time taken for each attack vector

## Attack Descriptions

1. **Data Tampering**: Attempts to send messages with spoofed sender information
2. **Replay Attack**: Tries to resend the same message content multiple times
3. **Spoofing (SSE)**: Attempts to establish SSE connections with fake agent IDs
4. **Prompt Injection**: Sends malicious prompts attempting to bypass restrictions
5. **SCA Impersonation**: Tries to connect with invalid privacy keys
6. **PII Leakage**: Tests if data from one session can leak to another
7. **Registry Pollution**: Creates multiple sessions to test resource exhaustion
8. **Leak Exposure**: Sends malformed payloads to trigger verbose error responses
9. **Compliance Gaps**: Based on data tampering results to assess audit reliability

## Troubleshooting

- Ensure the Coral server is running before starting the tests
- Check that the BASE_URL in the client matches your server configuration
- Verify your OpenAI API key is valid and has sufficient credits
- If experiencing connection issues, check firewall and network settings

## Notes

- This tool is for security testing purposes only
- Always run tests against servers you own or have explicit permission to test
- Results may vary depending on server configuration and implementation