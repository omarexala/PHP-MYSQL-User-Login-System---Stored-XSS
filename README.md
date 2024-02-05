# PHP-MYSQL-User-Login-System---Stored-XSS

Affected Web App: https://github.com/keerti1924/PHP-MYSQL-User-Login-System

Title: Stored XSS with the help of SQL Injection

Affected Component: /signup.php

CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

CVSS 3.1 Score: 3.1 (self - rated with the help of online CVSS calculator)

Impact: Cross-Site Scripting (XSS) vulnerability is a serious web security threat, allowing attackers to inject malicious scripts with diverse impacts. Users face data theft, session hijacking, and unwittingly performing unauthorized actions. Websites risk defacement, and attackers can exploit XSS for phishing, worm propagation, cookie theft, and SEO poisoning. Mitigation involves robust security measures like secure coding, input validation, output encoding, and regular security audits.

Proof of Concept: To reproduce this attack, an attacker can inject a script into the username field during the signup process. The payload '<script>alert("xss")</script>' was successfully accepted, leading to an alert being triggered for the user:
![proof of xss upon login](https://github.com/omarexala/PHP-MYSQL-User-Login-System---Stored-XSS/assets/159004359/283a12c5-7b6b-4fba-9cb5-1cb6d85467fb)

After verifying that Stored XSS is being allowed by the website, an attacker will try to inject an SQL Injection payload like:' '# ' in the update profile module wherein after injecting it, usernames for all users using the website will have an alert upon login.


Remediation: 
To mitigate the risks associated with Cross-Site Scripting (XSS) vulnerabilities, it is imperative to embrace secure coding practices. Rigorous input validation must be implemented on both client and server sides, coupled with the integration of output encoding mechanisms to thwart the execution of malicious scripts. The adoption of a robust Content Security Policy (CSP) is essential for curbing unauthorized script execution. Additionally, prioritize the incorporation of the "HttpOnly" and "Secure" flags in cookies for enhanced security. Tailor output encoding based on specific data usage contexts to fortify defenses. Elevate browser security by incorporating headers like "X-Content-Type-Options" and "X-Frame-Options." Regularly update software components to promptly address known vulnerabilities. Collectively, these measures fortify the resilience against XSS threats, providing a comprehensive defense for web applications against potential exploits.
