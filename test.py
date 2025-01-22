# test_waf.py
import requests
import time
import json

class WAFTester:
    def __init__(self, base_url="http://localhost"):
        self.base_url = base_url
        self.session = requests.Session()

    def test_request(self, method, path, headers=None, data=None, expected_status=None):
        try:
            response = self.session.request(
                method=method,
                url=f"{self.base_url}{path}",
                headers=headers,
                data=data,
                allow_redirects=False
            )
            result = {
                "status_code": response.status_code,
                "expected_status": expected_status,
                "headers": dict(response.headers),
                "body": response.text[:200] + "..." if len(response.text) > 200 else response.text
            }
            return result
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def run_tests(self):
        tests = [
            # Test 1: Normal request (should pass)
            {
                "name": "Normal GET request",
                "method": "GET",
                "path": "/",
                "expected_status": 200
            },
            
            # Test 2: SQL Injection attempt (should be blocked)
            {
                "name": "SQL Injection attempt",
                "method": "GET",
                "path": "/?id=1 UNION SELECT * FROM users",
                "expected_status": 403
            },
            
            # Test 3: XSS attempt (should be blocked)
            {
                "name": "XSS attempt",
                "method": "POST",
                "path": "/",
                "data": "<script>alert('xss')</script>",
                "expected_status": 403
            },
            
            # Test 4: Rate limiting
            {
                "name": "Rate limiting test",
                "method": "GET",
                "path": "/",
                "repeat": 150,  # Exceed the 100 requests/minute limit
                "expected_status": 429
            },
            
            # Test 5: Path traversal attempt (should be blocked)
            {
                "name": "Path traversal attempt",
                "method": "GET",
                "path": "/../../etc/passwd",
                "expected_status": 403
            },
            
            # Test 6: Command injection attempt (should be blocked)
            {
                "name": "Command injection attempt",
                "method": "POST",
                "path": "/",
                "data": {"cmd": "cat /etc/passwd | grep root"},
                "expected_status": 403
            },
            
            # Test 7: WAF status endpoint
            {
                "name": "WAF status check",
                "method": "GET",
                "path": "/waf/status",
                "expected_status": 200
            }
        ]

        results = []
        for test in tests:
            print(f"\nRunning test: {test['name']}")
            
            if test.get("repeat", 1) > 1:
                # Rate limiting test
                for i in range(test["repeat"]):
                    result = self.test_request(
                        test["method"],
                        test["path"],
                        test.get("headers"),
                        test.get("data"),
                        test["expected_status"]
                    )
                    print(f"Request {i+1}/{test['repeat']}: Status {result['status_code']}")
                    if result["status_code"] == 429:
                        print("Rate limit triggered successfully")
                        break
                    time.sleep(0.1)  # Small delay between requests
            else:
                result = self.test_request(
                    test["method"],
                    test["path"],
                    test.get("headers"),
                    test.get("data"),
                    test["expected_status"]
                )
                
                success = result.get("status_code") == test["expected_status"]
                print(f"Status: {'✅ Passed' if success else '❌ Failed'}")
                print(f"Expected status: {test['expected_status']}")
                print(f"Actual status: {result.get('status_code')}")
                
                results.append({
                    "test_name": test["name"],
                    "success": success,
                    "result": result
                })

        return results

if __name__ == "__main__":
    tester = WAFTester()
    results = tester.run_tests()
    
    # Print summary
    print("\n=== Test Summary ===")
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r["success"])
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")