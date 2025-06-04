from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware  # Import CORS middleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import zxcvbn
import re
import hashlib
import httpx
import logging
import math
from pathlib import Path

# Load a basic English dictionary for word detection
DICTIONARY_PATH = Path(__file__).parent / 'common_words.txt'
if DICTIONARY_PATH.exists():
    with open(DICTIONARY_PATH, 'r') as f:
        COMMON_WORDS = set(word.strip().lower() for word in f if word.strip())
else:
    # Fallback: a small set
    COMMON_WORDS = set([
        'password', 'letmein', 'welcome', 'monkey', 'dragon', 'football', 'iloveyou', 'admin', 'login', 'abc123',
        'starwars', 'qwerty', 'superman', 'pokemon', 'shadow', 'master', 'hello', 'freedom', 'whatever', 'trustno1'
    ])

KEYBOARD_PATTERNS = [
    'qwerty', 'asdfgh', 'zxcvbn', '12345', 'qazwsx', '1qaz2wsx', 'wasd', 'poiuy', 'lkjhg', 'mnbvc', 'pass', 'word'
]

LEET_MAP = str.maketrans('4301$!7', 'aeoisit')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

app = FastAPI()

# Add CORS middleware to allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Allow requests from your frontend origin
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allow all headers
)

class PasswordCheckRequest(BaseModel):
    password: str

class PasswordStrengthResponse(BaseModel):
    score: int
    feedback: dict
    custom_analysis: dict
    zxcvbn: dict

class PasswordStrengthChecker:
    def __init__(self, password):
        self.password = password

    def check_common_passwords(self):
        """Check if password is among common passwords"""
        return self.password.lower() in COMMON_WORDS

    def length_score(self):
        """Score based on password length"""
        length = len(self.password)
        if length < 8:
            return 0
        elif length < 12:
            return 1
        elif length < 16:
            return 2
        else:
            return 3
            
    def variety_score(self):
        """Score based on character variety"""
        score = 0
        if re.search(r'[a-z]', self.password):
            score += 1
        if re.search(r'[A-Z]', self.password):
            score += 1
        if re.search(r'\d', self.password):
            score += 1
        if re.search(r'[^A-Za-z0-9]', self.password):
            score += 1
        return score

    def consecutive_char_penalty(self):
        """Penalty for consecutive character patterns"""
        penalty = 0
        if re.search(r'[a-z]{3,}', self.password):
            penalty += 1
        if re.search(r'[A-Z]{3,}', self.password):
            penalty += 1
        if re.search(r'\d{3,}', self.password):
            penalty += 1
        return penalty

    def repeated_char_penalty(self):
        """Penalty for repeated characters"""
        penalty = 0
        chars = set()
        for c in self.password:
            if self.password.count(c) > 2 and c not in chars:
                penalty += 1
                chars.add(c)
        return min(penalty, 3)  # Cap the penalty

    def sequential_char_penalty(self):
        """Penalty for sequential characters"""
        sequences = ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789']
        penalty = 0
        
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in self.password or seq[i:i+3][::-1] in self.password:
                    penalty += 1
        
        return min(penalty, 3)  # Cap the penalty

    def middle_numbers_special_score(self):
        """Score for having numbers or special chars in the middle"""
        if len(self.password) < 3:
            return 0
            
        middle = self.password[1:-1]
        if re.search(r'[\d!@#$%^&*(),.?":{}|<>]', middle):
            return 1
        return 0

    def all_letters_penalty(self):
        """Penalty if password is all letters"""
        if re.match(r'^[a-zA-Z]+$', self.password):
            return 1
        return 0

    def all_numbers_penalty(self):
        """Penalty if password is all numbers"""
        if re.match(r'^\d+$', self.password):
            return 1
        return 0

    def entropy_score(self):
        # Shannon entropy estimation
        if not self.password:
            return 0
        pool = 0
        if re.search(r'[a-z]', self.password): pool += 26
        if re.search(r'[A-Z]', self.password): pool += 26
        if re.search(r'\d', self.password): pool += 10
        if re.search(r'[^A-Za-z0-9]', self.password): pool += 32
        entropy = math.log2(pool) * len(self.password) if pool else 0
        return entropy

    def contains_dictionary_word(self):
        pw = self.password.lower().translate(LEET_MAP)
        for word in COMMON_WORDS:
            if len(word) > 3 and word in pw:
                return True, word
        return False, None

    def contains_keyboard_pattern(self):
        pw = self.password.lower()
        for pat in KEYBOARD_PATTERNS:
            if pat in pw:
                return True, pat
        return False, None

    def contains_year_or_date(self):
        # Years from 1900 to current year + 2
        for year in range(1900, 2027):
            if str(year) in self.password:
                return True, str(year)
        # Simple date patterns
        if re.search(r'(0[1-9]|1[0-2])[\/-](0[1-9]|[12][0-9]|3[01])', self.password):
            return True, 'date'
        return False, None

    def is_passphrase(self):
        # 3+ words separated by space or - or _
        return bool(re.match(r'([A-Za-z]{3,}[\s\-_]){2,}[A-Za-z]{3,}', self.password))

    def get_strength(self):
        if self.check_common_passwords():
            return "Very Weak", "This is a commonly used password. Please choose something unique."

        score = 0
        feedback = []

        # Entropy
        entropy = self.entropy_score()
        if entropy < 28:
            feedback.append("Password entropy is very low. Use more character types and length.")
        elif entropy < 36:
            feedback.append("Password entropy is low. Consider making it longer or more complex.")
        elif entropy > 60:
            feedback.append("Excellent entropy!")
        score += min(int(entropy // 10), 6)  # up to 6 points for entropy

        # Dictionary word
        dict_found, dict_word = self.contains_dictionary_word()
        if dict_found:
            feedback.append(f"Avoid using dictionary/common words like '{dict_word}'.")
            score -= 2

        # Keyboard pattern
        pat_found, pat = self.contains_keyboard_pattern()
        if pat_found:
            feedback.append(f"Avoid keyboard patterns like '{pat}'.")
            score -= 2

        # Year/date
        year_found, year_val = self.contains_year_or_date()
        if year_found:
            feedback.append(f"Avoid using years or dates like '{year_val}'.")
            score -= 1

        # Passphrase bonus
        if self.is_passphrase() and len(self.password) > 16:
            feedback.append("Great! Your password looks like a passphrase.")
            score += 2

        # ...existing positive/negative scoring...
        length_points = self.length_score() * 2
        score += length_points
        if length_points < 2:
            feedback.append("Make your password longer (12+ characters recommended)")

        variety_points = self.variety_score() * 3
        score += variety_points
        if variety_points < 12:
            feedback.append("Use a mix of uppercase, lowercase, numbers, and special characters")

        score += self.middle_numbers_special_score()

        consecutive_penalty = self.consecutive_char_penalty() * 2
        score -= consecutive_penalty
        if consecutive_penalty > 0:
            feedback.append("Avoid sequences of similar character types (e.g., 'abc', '123')")

        repeated_penalty = self.repeated_char_penalty() * 2
        score -= repeated_penalty
        if repeated_penalty > 0:
            feedback.append("Avoid repeating characters")

        sequential_penalty = self.sequential_char_penalty() * 2
        score -= sequential_penalty
        if sequential_penalty > 0:
            feedback.append("Avoid sequential characters like '123' or 'abc'")

        all_letters_penalty = self.all_letters_penalty() * 2
        score -= all_letters_penalty
        if all_letters_penalty > 0:
            feedback.append("Don't use only letters")

        all_numbers_penalty = self.all_numbers_penalty() * 2
        score -= all_numbers_penalty
        if all_numbers_penalty > 0:
            feedback.append("Don't use only numbers")

        # Final strength
        if score >= 12:
            strength = "Very Strong"
        elif score >= 8:
            strength = "Strong"
        elif score >= 5:
            strength = "Medium"
        elif score >= 2:
            strength = "Weak"
        else:
            strength = "Very Weak"

        feedback_msg = "; ".join(feedback) if feedback else "Good password choice!"
        return strength, feedback_msg

    def get_detailed_analysis(self):
        strength, feedback = self.get_strength()
        analysis = {
            "overall_strength": strength,
            "feedback": feedback,
            "details": {
                "length": {
                    "value": len(self.password),
                    "score": self.length_score() * 2
                },
                "character_variety": {
                    "has_lowercase": bool(re.search(r'[a-z]', self.password)),
                    "has_uppercase": bool(re.search(r'[A-Z]', self.password)),
                    "has_digits": bool(re.search(r'\d', self.password)),
                    "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', self.password)),
                    "score": self.variety_score() * 3
                },
                "penalties": {
                    "consecutive_chars": -self.consecutive_char_penalty() * 2,
                    "repeated_chars": -self.repeated_char_penalty() * 2,
                    "sequential_chars": -self.sequential_char_penalty() * 2,
                    "all_letters": -self.all_letters_penalty() * 2,
                    "all_numbers": -self.all_numbers_penalty() * 2
                },
                "is_common_password": self.check_common_passwords()
            }
        }
        return analysis

@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "date": "2025-04-30"}

@app.post("/api/v1/pwned")
async def check_pwned_password(request: PasswordCheckRequest):
    """
    Checks if the password has been exposed in a public data breach using HaveIBeenPwned (k-anonymity).
    """
    try:
        sha1 = hashlib.sha1(request.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(HIBP_API_URL + prefix)
            if resp.status_code != 200:
                logging.error(f"HIBP API error: {resp.status_code}")
                return JSONResponse(status_code=502, content={"error": "HIBP API error"})
                
            hashes = resp.text.splitlines()
            for line in hashes:
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return {"pwned": True, "count": int(count)}
                    
        return {"pwned": False, "count": 0}
    except Exception as e:
        logging.error(f"Pwned check error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/v1/check_password", response_model=PasswordStrengthResponse)
async def check_password_v1(request: PasswordCheckRequest):
    """
    Checks the strength of a given password using both zxcvbn and custom analysis, and checks for breaches.
    """
    try:
        zxcvbn_result = zxcvbn.zxcvbn(request.password)
        custom_checker = PasswordStrengthChecker(request.password)
        custom_analysis = custom_checker.get_detailed_analysis()
        
        # Pwned check (async call)
        sha1 = hashlib.sha1(request.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(HIBP_API_URL + prefix)
            pwned_count = 0
            
            if resp.status_code == 200:
                hashes = resp.text.splitlines()
                for line in hashes:
                    hash_suffix, count = line.split(":")
                    if hash_suffix == suffix:
                        pwned_count = int(count)
                        break
                        
        feedback = {
            "warnings": zxcvbn_result["feedback"].get("warning", []),
            "suggestions": zxcvbn_result["feedback"].get("suggestions", []),
            "custom": custom_analysis["feedback"],
            "pwned": pwned_count
        }
        
        logging.info(f"Password checked. Pwned: {pwned_count}")
        
        return {
            "score": zxcvbn_result["score"],
            "feedback": feedback,
            "custom_analysis": custom_analysis,
            "zxcvbn": zxcvbn_result
        }
        
    except Exception as e:
        logging.error(f"Password check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ping")
async def ping():
    return "pong"

@app.post("/check_password", response_model=PasswordStrengthResponse)
async def check_password(request: PasswordCheckRequest):
    """
    Checks the strength of a given password using both zxcvbn and custom analysis.
    """
    try:
        zxcvbn_result = zxcvbn.zxcvbn(request.password)
        custom_checker = PasswordStrengthChecker(request.password)
        custom_analysis = custom_checker.get_detailed_analysis()
        
        # Use zxcvbn score (0-4) for compatibility with frontend
        return {
            "score": zxcvbn_result["score"],
            "feedback": zxcvbn_result["feedback"],
            "custom_analysis": custom_analysis,
            "zxcvbn": zxcvbn_result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
