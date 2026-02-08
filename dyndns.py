# BSD 3-Clause License
#
# Copyright (c) 2023, Brendan Bank
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# TODO 
# - allow for wildcard

from flask import Flask, request, make_response
from os import environ
from os import path
from dotenv import load_dotenv
import re
import hmac
import bcrypt

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

from lib import log, AccountFactory



ENV_VARS = [ 'USERNAME', 'PASSWORD']

for ENV in ENV_VARS:
    if not environ.get(ENV):
        log.critical(f'Enviroment Variable = {ENV} is not set!')
        exit (1)
    else:
        log.debug(f'Enviroment Variable {ENV} is set')

app = Flask(__name__)

Accounts = AccountFactory()

def httpReply(text, returncode=200):
    response = make_response(text, returncode)
    response.mimetype = "text/plain"
    return response
    
@app.route("/nic/update")
def updateDydns():
    myip = request.args.get("myip")
    

    hostnames = request.args.get("hostname")
    
    auth = request.authorization
    
    
    if (auth):
        username=auth.username
        password=auth.password
    else:
        username = request.args.get("username")
        password = request.args.get("password")
    

    url = re.sub(r"password=[^\&]*","password=********", request.url)
    ip = request.headers.get('X-Forwarded-For') or request.remote_addr

    if not myip:
        myip = ip
    

    if (password and username):
        hashed_password = str(environ.get('PASSWORD'))
        valid_user = hmac.compare_digest(environ.get('USERNAME'), username)
        valid_pass = bcrypt.checkpw(password.encode('utf8'), hashed_password.encode())
        if not valid_user or not valid_pass:
            log.critical(f'invalid username or password')
            return httpReply("badauth - invalid username or password", returncode=403)
    else:
        log.critical(f'invalid username or password')
        return httpReply("badauth - invalid username or password", returncode=403)

    updatetype = request.args.get("updatetype", default="aws")
    
    account = Accounts.get({"service": updatetype})
    
    if (not account):
        log.critical(f'invalid updatetype')
        return httpReply("badauth - invalid updatetype", returncode=400)

    ip = account.getip(ip)
    myip = account.getip(myip)

    log.info (f'received request from {ip} to host: {request.host}  url: {url}')

    if not myip or not hostnames:
        log.critical(f'invalid IP address {myip} or hostnames {hostnames}')
        return httpReply(f'911 invalid IP address or hostnames, these cannot be empty.', returncode=400)

    log.info (f'received request from user {username} for myip = {myip}, hostname = {hostnames}')

    ipType = account.getiptype(myip)
    
    if (not ipType):
        log.critical(f'invalid IP address {myip}')
        return httpReply(f'911 invalid IP address {myip}', returncode=400)
        
    hostnamesObj = account.isvalidhostname(hostnames)
    
    if (not hostnamesObj):
        log.critical(f'invalid hostname {hostnames}')
        return httpReply(f'notfqdn invalid hostname {hostnames}', returncode=400)
    
    hostname_zones = account.hostnameperzone(hostnamesObj)
    
    if not hostname_zones:
        return httpReply("nohost - The hostname/domain specified does not exist in this user account.", returncode=400)
    
    log.debug(f'hostnames per zone {hostname_zones}')
    
    
    if not account.createrecords(str(myip), hostname_zones, rtype=ipType):
        log.critical(f'account.createrecords returned false')
        return httpReply(f'911 - Something went wrong!', returncode=400)
    
    return httpReply("good")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)

