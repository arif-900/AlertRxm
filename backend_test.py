import requests
import sys
import json
import time
from datetime import datetime

class AlertRxAPITester:
    def __init__(self, base_url="https://rxwatch-system.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_user_email = f"test_user_{datetime.now().strftime('%H%M%S')}@test.com"
        self.test_user_password = "TestPass123!"
        self.test_user_name = "Test User"

    def log_test(self, name, success, details=""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED {details}")
        else:
            print(f"❌ {name} - FAILED {details}")
        return success

    def make_request(self, method, endpoint, data=None, auth_required=False):
        """Make HTTP request with proper headers"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {'Content-Type': 'application/json'}
        
        if auth_required and self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)
            
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
            return None

    def test_api_root(self):
        """Test API root endpoint"""
        response = self.make_request('GET', '')
        if response and response.status_code == 200:
            data = response.json()
            return self.log_test("API Root", 
                               "AlertRx" in data.get('message', ''), 
                               f"- Message: {data.get('message', 'No message')}")
        return self.log_test("API Root", False, f"- Status: {response.status_code if response else 'No response'}")

    def test_signup_invalid_password(self):
        """Test signup with invalid password"""
        weak_passwords = [
            ("weak", "Too short"),
            ("weakpassword", "No uppercase, number, special char"),
            ("WeakPassword", "No number, special char"),
            ("WeakPassword123", "No special char"),
        ]
        
        all_rejected = True
        for password, reason in weak_passwords:
            user_data = {
                "email": f"weak_{datetime.now().strftime('%H%M%S%f')}@test.com",
                "full_name": "Weak Password User",
                "password": password
            }
            
            response = self.make_request('POST', 'auth/signup', user_data)
            if response and response.status_code == 400:
                print(f"    ✅ Password '{password}' rejected ({reason})")
            else:
                print(f"    ❌ Password '{password}' accepted - should be rejected ({reason})")
                all_rejected = False
        
        return self.log_test("Signup Password Validation", all_rejected, 
                           "- Weak passwords properly rejected")

    def test_signup_valid(self):
        """Test valid user signup"""
        user_data = {
            "email": self.test_user_email,
            "full_name": self.test_user_name,
            "password": self.test_user_password
        }
        
        response = self.make_request('POST', 'auth/signup', user_data)
        if response and response.status_code == 200:
            data = response.json()
            self.user_id = data.get('id')
            return self.log_test("Valid Signup", True, 
                               f"- User ID: {self.user_id}")
        return self.log_test("Valid Signup", False, 
                           f"- Status: {response.status_code if response else 'No response'}")

    def test_signup_duplicate_email(self):
        """Test signup with duplicate email"""
        user_data = {
            "email": self.test_user_email,  # Same email as previous test
            "full_name": "Duplicate User",
            "password": self.test_user_password
        }
        
        response = self.make_request('POST', 'auth/signup', user_data)
        return self.log_test("Duplicate Email Signup", 
                           response and response.status_code == 400,
                           "- Duplicate email properly rejected")

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        # Test wrong password
        login_data = {
            "email": self.test_user_email,
            "password": "WrongPassword123!"
        }
        
        response = self.make_request('POST', 'auth/login', login_data)
        wrong_password = response and response.status_code == 401
        
        # Test wrong email
        login_data = {
            "email": "nonexistent@test.com",
            "password": self.test_user_password
        }
        
        response = self.make_request('POST', 'auth/login', login_data)
        wrong_email = response and response.status_code == 401
        
        return self.log_test("Invalid Login Credentials", 
                           wrong_password and wrong_email,
                           "- Wrong password and email properly rejected")

    def test_login_valid(self):
        """Test valid login"""
        login_data = {
            "email": self.test_user_email,
            "password": self.test_user_password
        }
        
        response = self.make_request('POST', 'auth/login', login_data)
        if response and response.status_code == 200:
            data = response.json()
            self.token = data.get('access_token')
            return self.log_test("Valid Login", True, 
                               f"- Token received: {bool(self.token)}")
        return self.log_test("Valid Login", False, 
                           f"- Status: {response.status_code if response else 'No response'}")

    def test_auth_me(self):
        """Test getting current user info"""
        response = self.make_request('GET', 'auth/me', auth_required=True)
        if response and response.status_code == 200:
            data = response.json()
            return self.log_test("Get Current User", 
                               data.get('email') == self.test_user_email,
                               f"- Email: {data.get('email')}")
        return self.log_test("Get Current User", False, 
                           f"- Status: {response.status_code if response else 'No response'}")

    def test_symptom_risk_assessment(self):
        """Test symptom logging with different risk levels"""
        test_cases = [
            # Low risk case
            {
                "name": "Low Risk Symptoms",
                "data": {
                    "symptoms": {
                        "temperature": "98.6",
                        "heart_rate": "72",
                        "blood_pressure_systolic": "120",
                        "pain_level": "2"
                    },
                    "custom_symptoms": "Mild headache"
                },
                "expected_severity": "low"
            },
            # Medium risk case
            {
                "name": "Medium Risk Symptoms", 
                "data": {
                    "symptoms": {
                        "temperature": "101.5",
                        "heart_rate": "105",
                        "blood_pressure_systolic": "150",
                        "pain_level": "6"
                    },
                    "custom_symptoms": "Feeling dizzy"
                },
                "expected_severity": "medium"
            },
            # High risk case
            {
                "name": "High Risk Symptoms",
                "data": {
                    "symptoms": {
                        "temperature": "104.0",
                        "heart_rate": "130",
                        "blood_pressure_systolic": "190",
                        "pain_level": "9",
                        "breathing_difficulty": "severe"
                    },
                    "custom_symptoms": "Chest pain and difficulty breathing"
                },
                "expected_severity": "high"
            }
        ]
        
        all_passed = True
        for test_case in test_cases:
            response = self.make_request('POST', 'symptoms', test_case["data"], auth_required=True)
            if response and response.status_code == 200:
                data = response.json()
                severity = data.get('severity_prediction')
                passed = severity == test_case["expected_severity"]
                self.log_test(test_case["name"], passed, 
                            f"- Expected: {test_case['expected_severity']}, Got: {severity}")
                if not passed:
                    all_passed = False
            else:
                self.log_test(test_case["name"], False, 
                            f"- Status: {response.status_code if response else 'No response'}")
                all_passed = False
        
        return all_passed

    def test_get_symptoms(self):
        """Test retrieving user symptoms"""
        response = self.make_request('GET', 'symptoms', auth_required=True)
        if response and response.status_code == 200:
            data = response.json()
            return self.log_test("Get Symptoms", 
                               isinstance(data, list) and len(data) > 0,
                               f"- Found {len(data)} symptoms")
        return self.log_test("Get Symptoms", False, 
                           f"- Status: {response.status_code if response else 'No response'}")

    def test_get_alerts(self):
        """Test retrieving alert history"""
        response = self.make_request('GET', 'alerts', auth_required=True)
        if response and response.status_code == 200:
            data = response.json()
            return self.log_test("Get Alert History", 
                               isinstance(data, list),
                               f"- Found {len(data)} alerts")
        return self.log_test("Get Alert History", False, 
                           f"- Status: {response.status_code if response else 'No response'}")

    def test_unauthorized_access(self):
        """Test accessing protected endpoints without token"""
        endpoints = ['auth/me', 'symptoms', 'alerts']
        all_protected = True
        
        for endpoint in endpoints:
            response = self.make_request('GET', endpoint, auth_required=False)
            if not (response and response.status_code == 401):
                all_protected = False
                break
        
        return self.log_test("Unauthorized Access Protection", all_protected,
                           "- All protected endpoints require authentication")

    def run_all_tests(self):
        """Run all tests in sequence"""
        print("🚀 Starting AlertRx API Testing...")
        print(f"📍 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Basic API tests
        self.test_api_root()
        
        # Authentication tests
        self.test_signup_invalid_password()
        self.test_signup_valid()
        self.test_signup_duplicate_email()
        self.test_login_invalid_credentials()
        self.test_login_valid()
        self.test_auth_me()
        
        # Authorization tests
        self.test_unauthorized_access()
        
        # Symptom and alert tests (require authentication)
        if self.token:
            self.test_symptom_risk_assessment()
            self.test_get_symptoms()
            self.test_get_alerts()
        else:
            print("⚠️  Skipping authenticated tests - no token available")
        
        # Print summary
        print("=" * 60)
        print(f"📊 TEST SUMMARY:")
        print(f"✅ Passed: {self.tests_passed}/{self.tests_run}")
        print(f"❌ Failed: {self.tests_run - self.tests_passed}/{self.tests_run}")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print("⚠️  Some tests failed - check logs above")
            return 1

def main():
    tester = AlertRxAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())