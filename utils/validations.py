from datetime import datetime, timedelta
import re

def vpassword(password):
    if len(password) < 8 or len(password) > 20 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password) or not any(char.islower() for char in password):
        return False
    return True

def vdate(date):
    try:
        datetime.strptime(date, '%Y-%m-%d')
        if datetime.strptime(date, '%Y-%m-%d') > datetime.now() - timedelta(days=365):
            return False
        return True
    except ValueError:
        return False
def vemail(email):
    print('email: ', email)
    pattern = "^[a-zA-Z0-9-_]+@[a-zA-Z0-9]+\.[a-z]{1,3}$"
    if re.match(pattern, email): #and len(email) > 7 and len(email) < 100 and email.count('@') == 1:
        return True
    return False
