from mitmproxy import http

class SSELogger:
    def sse_message(self, flow: http.HTTPFlow):
        """
        This function is called by mitmproxy for every single SSE message.
        """
        if not flow.request.is_sse or not flow.response.is_sse:
             return

        message = flow.messages[-1]
        
        if message.from_client:
            print("\n--- [MITM LOG] Message FROM CLIENT ---> ---")
            print(f"Data: {message.data}")
            print("-------------------------------------------\n")
        else: # From Server
            print("\n--- [MITM LOG] Message FROM SERVER <--- ---")
            print(f"Data: {message.data}")
            print("-------------------------------------------\n")

addons = [SSELogger()]