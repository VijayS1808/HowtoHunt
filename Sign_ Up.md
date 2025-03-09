1. Duplicate Registration / Overwrite Existing User (Email Case Sensitivity) 📡📡📡
   
    • Vulnerability Type: User Enumeration / Account Takeover
   
    • Steps to Reproduce:
   ```
        1. Sign up with user@first.org and password Password123. 
        2. Log out, then sign up again using User@first.org (note the change in capitalization). 
        3. Confirm that both accounts can be used to log in.
   ```
    • Expected Behavior: The system should normalize email addresses and prevent multiple accounts being created with case-sensitive emails. 
    • Impact: Medium — An attacker can create duplicate accounts or gain unauthorized access to existing accounts. 
    • Severity: High 
    • CVSS Base Score: 7.5 (High) 
    • HackerOne Report: HackerOne Report Example 

3. Denial of Service (DoS) via Long Input Strings 📡📡📡
   
    • Vulnerability Type: DoS
   
    • Steps to Reproduce:
   ```
        1. Navigate to the signup form. 
        2. Enter a password field with 100,000 characters. 
        3. Submit the form. 
        4. Observe the server crash or slow response.
   ```
    • Expected Behavior: The system should limit the input length and handle large strings gracefully. 
    • Impact: High — Server crashes or slowdowns due to CPU/memory exhaustion. 
    • Severity: Critical 
    • CVSS Base Score: 9.0 (Critical) 
    • HackerOne Report: HackerOne Report Example 

5. Cross-Site Scripting (XSS) in Signup Fields 📡📡📡
   
    • Vulnerability Type: XSS
   
    • Steps to Reproduce:
   ```
        1. Inject <svg/onload=alert('XSS')> into the username field. 
        2. Submit the form and observe the result. 
        3. Verify that the script is executed when the page loads.
   ```
    • Expected Behavior: The system should sanitize user input to prevent malicious scripts from being executed. 
    • Impact: High — Attackers can execute malicious scripts on users’ browsers, leading to data theft or session hijacking. 
    • Severity: Critical 
    • CVSS Base Score: 8.0 (High) 
    • HackerOne Report: HackerOne Report Example 

7. No Rate Limiting on Signup Page 📡📡📡
   
    • Vulnerability Type: Rate Limiting / Brute Force
   
    • Steps to Reproduce:
   ```
        1. Use Burp Suite Intruder to send multiple signup requests to the form with different email addresses. 
        2. Observe that the application does not block or throttle repeated requests.
   ```
    • Expected Behavior: The system should have rate limiting in place to prevent brute force attacks. 
    • Impact: High — An attacker can create an overwhelming number of fake accounts, filling the system with invalid data. 
    • Severity: High 
    • CVSS Base Score: 7.5 (High) 
    • HackerOne Report: HackerOne Report Example 

9. Insufficient Email Verification (Email Bypass) 📡📡📡

    • Vulnerability Type: Email Verification Bypass
   
    • Steps to Reproduce:
   ```
        1. Sign up with attacker@mail.com. 
        2. Receive the verification email, but do not open the link. 
        3. Change the email to victim@mail.com in account settings. 
        4. Access the verification link in the attacker’s inbox. 
        5. Verify the victim’s email address using the link from the attacker’s inbox.
   ```
    • Expected Behavior: The system should not allow email verification links to be reused. 
    • Impact: High — An attacker can bypass the email verification process and hijack a victim’s email. 
    • Severity: Critical 
    • CVSS Base Score: 9.0 (Critical) 
    • HackerOne Report: HackerOne Report Example 

11. Path Overwrite (Hijacking Profile URL) 📡📡📡
    
    • Vulnerability Type: Path Traversal
    
    • Steps to Reproduce:
    ```
        1. Sign up with the username index.php. 
        2. Access first.org/index.php and check if your profile page appears instead of the website’s homepage.
    ```
    
    • Expected Behavior: The system should prevent the use of reserved system filenames like index.php, login.php, etc., as usernames.
    • Impact: High — An attacker can hijack important URLs and make the site behave unexpectedly. 
    • Severity: Critical 
    • CVSS Base Score: 8.5 (High) 
    • HackerOne Report: HackerOne Report Example 

13. SQL Injection in Signup Form 📡📡📡
    
    • Vulnerability Type: SQL Injection
    
    • Steps to Reproduce:
    ```
        1. Inject SQL payload ' OR 1=1 -- into the email or username field. 
        2. Submit the form and check if the server returns unexpected results or data.
    ```
    
    • Expected Behavior: The system should sanitize inputs and prevent SQL injection attacks. 
    • Impact: Critical — An attacker can potentially gain unauthorized access to the database and execute arbitrary queries. 
    • Severity: Critical 
    • CVSS Base Score: 9.0 (Critical) 
    • HackerOne Report: HackerOne Report Example 

15. Weak CAPTCHA on Signup Page 📡📡📡
    
    • Vulnerability Type: CAPTCHA Bypass
    
    • Steps to Reproduce:
    ```
        1. Use a bot or automated tool to bypass the CAPTCHA on the signup page. 
        2. Sign up multiple fake accounts automatically.
    ```
    • Expected Behavior: The CAPTCHA should prevent automated bots from signing up. 
    • Impact: Medium — Bots can create fake accounts, overwhelming the system. 
    • Severity: Medium 
    • CVSS Base Score: 5.3 (Medium) 
    • HackerOne Report: HackerOne Report Example 

17. Weak Password Validation 📡📡📡
    
    • Vulnerability Type: Weak Password Policy
    
    • Steps to Reproduce:
    ```
        1. Sign up using a weak password like 12345 or password. 
        2. Verify the password is accepted.
    ```
    
    • Expected Behavior: The system should enforce a minimum password length and complexity requirements. 
    • Impact: Medium — Weak passwords can be easily cracked, compromising user accounts. 
    • Severity: Medium 
    • CVSS Base Score: 5.0 (Medium) 
    • HackerOne Report: HackerOne Report Example 

19. Information Disclosure in Error Messages 📡📡📡
    
    • Vulnerability Type: Information Disclosure
    
    • Steps to Reproduce:
    ```
        1. Attempt to sign up with an already registered email address. 
        2. Observe the error message.
    ```
    
    • Expected Behavior: The system should provide a generic error message without revealing information about the account status. 
    • Impact: Medium — Attackers can enumerate valid usernames or email addresses. 
    • Severity: Medium 
    • CVSS Base Score: 5.3 (Medium) 
    • HackerOne Report: HackerOne Report Example 

21. Insecure Direct Object References (IDOR) on Signup Form 📡📡📡
    
    • Vulnerability Type: IDOR
    
    • Steps to Reproduce:
    ```
        1. Sign up and access first.org/profile/{user-id}. 
        2. Try modifying the user-id in the URL to access other users' profiles.
    ```
    • Expected Behavior: The system should enforce proper access controls to prevent unauthorized access to other users' profiles. 
    • Impact: High — Attackers can access data belonging to other users. 
    • Severity: High 
    • CVSS Base Score: 7.5 (High) 
    • HackerOne Report: HackerOne Report Example 

23. Unencrypted Password Transmission Over HTTP 📡📡📡
    
    • Vulnerability Type: Insecure Communication
    
    • Steps to Reproduce:
    ```
        1. Navigate to the signup page over HTTP instead of HTTPS. 
        2. Use a packet sniffer to capture the password transmitted in plaintext.
    ```
    • Expected Behavior: The system should ensure that passwords are transmitted securely over HTTPS. 
    • Impact: Critical — Credentials are exposed to attackers via Man-in-the-Middle attacks. 
    • Severity: Critical 
    • CVSS Base Score: 9.3 (Critical) 
    • HackerOne Report: HackerOne Report Example 

25. Account Enumeration via Signup 📡📡📡
    
    • Vulnerability Type: Account Enumeration
    
    • Steps to Reproduce:
    ``
        1. Attempt to sign up with various known email addresses. 
        2. Observe if the application provides different responses for registered vs unregistered emails.
    ```
    • Expected Behavior: The system should not disclose whether an email is already registered. 
    • Impact: Medium — Attackers can enumerate valid email addresses for phishing or brute-force attacks. 
    • Severity: Medium 
    • CVSS Base Score: 5.3 (Medium) 
    • HackerOne Report: HackerOne Report Example 

27. Weak Session Management After Signup 📡📡📡
    
    • Vulnerability Type: Session Management Flaw
    
    • Steps to Reproduce:
    ```
        1. Sign up and then log out. 
        2. Attempt to access protected areas of the site.
    ```
    • Expected Behavior: The session should be invalidated when logging out to prevent unauthorized access. 
    • Impact: Medium — Improper session handling can lead to unauthorized access. 
    • Severity: Medium 
    • CVSS Base Score: 5.0 (Medium) 
    • HackerOne Report: HackerOne Report Example 

29. Improper Input Validation (Script Injection in Email Field) 📡📡📡
    
    • Vulnerability Type: Input Validation Flaw
    
    • Steps to Reproduce:
    ```
        1. Inject a script like "><script>alert('XSS')</script> into the email field. 
        2. Submit the form and observe if the script executes.
    ```
    • Expected Behavior: The system should properly sanitize all user inputs to prevent script injection. 
    • Impact: High — XSS vulnerabilities allow attackers to steal session cookies or execute malicious actions. 
    • Severity: High 
    • CVSS Base Score: 7.5 (High) 
    • HackerOne Report: HackerOne Report Example 
