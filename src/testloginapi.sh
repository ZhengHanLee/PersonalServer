
# change this number as per instruction to avoid conflicts.
PORT=10000

# to test against a working implementation (and see the intended responses)
# change this variable, e.g.
#URL=http://hazelnut.rlogin:12345
URL=http://localhost:${PORT}

# the file in which curl stores cookies across runs
COOKIEJAR=cookies.txt


# clear cookies
/bin/rm ${COOKIEJAR}

# test authentication
# this should result in a cookie being issued that embeds the JWT token
curl -v -H "Content-Type: application/json" \
     -c ${COOKIEJAR} \
     -X POST \
     -d '{"username":"user0","password":"thepassword"}' \
    ${URL}/api/login

# this should succeed if the password was correct
# curl presents the cookie from the previous request
curl -v \
    -b ${COOKIEJAR} \
    ${URL}/api/login

# create a 'private' folder first for your server, and
# put a file `secret.txt` in it.
# this should fail since credentials were not presented in the request
curl -v \
    ${URL}/private/secret.txt

# this should succeed since credentials are included (via the cookie jar)
curl -v \
    -b ${COOKIEJAR} \
    ${URL}/private/secret.txt

# now log out
curl -v -X POST \
    -c ${COOKIEJAR} \
    ${URL}/api/logout

# this should fail since the cookie should have been removed from the cookie jar
curl -v \
    -b ${COOKIEJAR} \
    ${URL}/private/secret.txt
