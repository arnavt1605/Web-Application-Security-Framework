1. Reflected Cross-Site Scripting (XSS) is a web security vulnerability where an attacker injects malicious code, usually JavaScript, into a URL. When a victim clicks this specially crafted link, the request is sent to the website, which then "reflects" the malicious script back in the response to the victim's browser. The browser, trusting the website, executes the script, allowing the attacker to perform actions on behalf of the user, such as stealing their session cookies. Think of it like a trick where you ask a website "What is my name?" but your name is a command like "say boo!"; the website, not realizing it's a command, simply echoes "Your name is say boo!" back at you, and your browser follows the command. The attack is not stored on the website permanently and requires a user to click a malicious link each time.



2. User controlled data made its way from the request page to the response page browser without being escaped or sanitozed and the browser parsed it as code and ran it in the page's origin


3. Injected a basic JavaScript payload (<script>alert('XSS Proof')</script>). The server reflected this script back to my browser without proper sanitization, causing it to execute.
The resulting alert box proves that an attacker could run malicious scripts in the context of any user who clicks a crafted link. This could be used to steal session cookies, redirect users to malicious sites, or deface the web page, making it another critical vulnerability that the WAF must address.
