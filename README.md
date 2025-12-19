# SWAPPER

A Burp Suite Extension for automated match and replace of tokens, CSRF values, and authentication headers using regex pattern matching. **Supports both XML and JSON formats**.

### Features
- **Automatic token refresh:** Fetches fresh tokens every 4 minutes (240 seconds) by default  - adjustable based on token TTL. Has a per-request refresh that can be used for strict validation scenarios.
- **Multipe pattern extraction:** SWAPPER supports multiple match/replace patterns. Use as many patterns as you want
- **Regex matching:** Because who doesn't love using regex!  

### Use Cases
- **XML:** SOAP API, Legacy systems, SAML
- **JSON:** OAuth 2.0, REST APIs, GraphQL authentication, Microsoft Graph API
- **Advanced Patterns:** CSRF bypassing, MFA flows, per-request mode when session token is invalidated after single use

## Install  
Burp Suite needs the Python environment configured. Add the reference to the Jython JAR file in extension settings.  

From the Extensions setting, in the Installed tab, select `add` and choose Python as the extension type. Then load swapper.py. That is all there is. 

## HOW TO USE:  
Example from OWASP JuiceShop at `https://juice-shop.herokuapp.com` to get the Bearer token from endpoint, match the request header, and what to update the match with.  

### Right-click on the request in Target/History that issues the token and select "Send to SWAPPER" to populate fields  

![Send to SWAPPER](/images/send_to.png)  

### Modify the request details to create your token request  
Fields populate from the request sent to SWAPPER. If you need to modify username/password/whatever, you can modify here.

![Token Request](/images/swapper_config.png)  

### Set up regex patterns for token extraction/replacement  
You are able to add multiple patterns to match/replace. Select `Add Another Regex Pair` if multiple patterns are needed.  

There are three options:  

- **Response Regex** This extracts the token from the response from the request in SWAPPER Configuration.  
- **Request Regex** This searches all requests, for the selected tools, for the pattern that needs to be replaced.    
- **Replacement** This is the replacement for the pattern matched by the `Request Regex`. Note that `{token}` is the extracted value from the response.  

![Regex Config](/images/regex_config.png)  
 
### Test your configuration  
The Status box will show the matches, to verify the regex is how you intended it to be. If multiple regex patterns are in use, testing will check all patterns.  

The button `Test Token Request` will send the request from SWAPPER Configuration and check the response from the regex in `Response Regex`.  The Status box will show the match or indicate no pattern was matched.  

![Status Match](/images/status_response.png)  

To test the request pattern, in History/Target/Repeater, right click the request and select `Test Request Regex`. The pattern in `Request Regex` will be used to search the selected request. The Status box will show the matched pattern or indicate that no value matches.  

![Request Regex Match](/images/status_request_match.png)  

### Enable tools and auto-refresh as needed  
- **Enable Extension** Start and stop SWAPPER

- **Tools** Choose what tools you want SWAPPER to swap out tokens for.  

- **Enable Auto-refresh** Change time to request new token. Disabling `Enabling Auto-refresh` will send a new token request for each request.  

![Tools](/images/tools.png)  

### Troubleshooting  
Remember to save configuration to update changes. Be sure to check Logger/Logger++ to verify your requests are being updated.  

The image below shows SWAPPER sending a request to endpoint `/rest/user/login` and then Intruder sending payloads to the search endpoint.  

![Logger](/images/logger.png)  

Verify the token that was issued in the SWAPPER request.  

![Get Token](/images/get_token.png)  

Ensure the token issued was used in the Intruder attack.  

![New Token](/images/new_token.png)    
