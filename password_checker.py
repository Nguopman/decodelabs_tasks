import string

def evaluate_password(password: str) -> dict:
    length = len(password)
    
    # 1. Immediate length check (< 8 characters = immediate fail)
    if length < 8:
        return {
            "score": 0,
            "status": "Weak",
            "feedback": ["Password length is below 8 characters (high brute-force risk)."]
        }
    
    # 2. Linear character checks using Pythonic short-circuiting
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in string.punctuation for char in password)
    
    criteria_met = sum([has_upper, has_lower, has_digit, has_symbol])
    feedback = []
    
    if not has_upper:
        feedback.append("Missing uppercase letters [A-Z].")
    if not has_lower:
        feedback.append("Missing lowercase letters [a-z].")
    if not has_digit:
        feedback.append("Missing numeric digits [0-9].")
    if not has_symbol:
        feedback.append("Missing special symbols/punctuation.")
        
    # 3. Risk classification logic
    if length >= 12 and criteria_met == 4:
        status = "Strong"
    elif length >= 8 and criteria_met >= 3:
        status = "Medium"
    else:
        status = "Weak"
        
    return {
        "score": criteria_met + (1 if length >= 12 else 0),
        "status": status,
        "feedback": feedback
    }

def main():
    print("=" * 45)
    print("  DecodeLabs: Password Strength Analyzer")
    print("=" * 45)
    
    while True:
        pwd = input("\nEnter a password to evaluate (or 'exit' to quit): ").strip()
        if pwd.lower() == "exit":
            break
            
        result = evaluate_password(pwd)
        
        print(f"[*] Strength Classification : {result['status']}")
        print(f"[*] Entropy / Criteria Score: {result['score']}/5")
        
        if result["feedback"]:
            print("[!] Security Recommendations:")
            for item in result["feedback"]:
                print(f"    - {item}")
        else:
            print("[+] Password adheres to strict policy standards.")

if __name__ == "__main__":
    main()
