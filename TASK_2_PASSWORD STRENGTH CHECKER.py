import re

def assess_password_strength(password):
    score = 0
    length_criteria = len(password) >= 8
    complexity_criteria = (
        re.search(r'[A-Z]', password) and  
        re.search(r'[a-z]', password) and  
        re.search(r'[0-9]', password) and   
        re.search(r'[\W_]', password)       
    )
    
    # Length check
    if length_criteria:
        score += 1
    
    # Complexity check
    if complexity_criteria:
        score += 1
    
    # Uniqueness check (against a simple common password list)
    common_passwords = {"password", "123456", "12345678", "qwerty", "abc123"}
    if password.lower() not in common_passwords:
        score += 1
    return score

def get_strength_message(score):
    if score == 0:
        return "Very Weak"
    elif score == 1:
        return "Weak"
    elif score == 2:
        return "Moderate"
    elif score == 3:
        return "Strong"
    else:
        return "Very Strong"

def main():
    password = input("Enter your password: ")
    score = assess_password_strength(password)
    strength_message = get_strength_message(score)
    print(f"Password strength: {strength_message}")

if __name__ == "__main__":
    main()
