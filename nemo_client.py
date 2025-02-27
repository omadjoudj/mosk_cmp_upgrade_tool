#!/usr/bin/python

from http.client import HTTPSConnection
from base64 import b64encode

def rest_client(url, username, password):
    # Extract hostname and path
    hostname = url.replace("https://", "").split('/')[0]
    path = '/' + '/'.join(url.split('/')[3:])
    
    # Create auth header
    token = b64encode(f"{username}:{password}".encode('utf-8')).decode("ascii")
    headers = {'Authorization': f'Basic {token}'}
    
    # Make request
    conn = HTTPSConnection(hostname)
    conn.request('GET', path, headers=headers)
    response = conn.getresponse()
    return response

if __name__ == "__main__":
    # Example usage
    r = rest_client('', '', '')
    print(r.read())
