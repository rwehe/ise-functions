import os,\
        re,\
        json,\
        requests,\
        traceback,\
        xmltodict


########################
# Endpoint Search by IP Address
# Returns raw XML session data
# Returns None on failure
def get_sess_by_ip(server,username,password,ip):
    s = requests.session()
    s.auth = (username,password)
    url = f'https://{server}/admin/API/mnt/Session/EndPointIPAddress/{ip}'
    try:
        r = s.get(url,verify=False)
        if r.status_code == 200:
            return r.text
    except:
        print(f'Error: \n{traceback.format_exc()}')
    return None


########################
# CoA Session Terminate
# No Port Bounce or Shutdown
# Compatible with VPN and Wireless endpoints
# Returns True/False
def coa_term_by_ip(server,username,password,ip):
    s = requests.session()
    s.auth = (username,password)
    sess = get_sess_by_ip(server,username,password,ip)
    if not sess:
        return False
    data = xmltodict.parse(sess)
    mac = data['sessionParameters']['calling_station_id']
    psn = data['sessionParameters']['acs_server']
    url = f'https://{server}/admin/API/mnt/CoA/Disconnect/{psn}/{mac}/0'
    try:
        r = s.get(url,verify=False)
        if (r.status_code == 200) and (
                xmltodict.parse(r.text)['remoteCoA']['results'] == 'true'):
            return True
    except:
        print(f'Error: \n{traceback.format_exc()}')
    return False


########################
# CoA Session ReAuth
# No Port Bounce or Shutdown
# Compatible with VPN and Wireless endpoints
# Returns True/False
def coa_reauth_by_ip(server,username,password,ip):
    s = requests.session()
    s.auth = (username,password)
    sess = get_sess_by_ip(server,username,password,ip)
    if not sess:
        return False
    data = xmltodict.parse(sess)
    mac = data['sessionParameters']['calling_station_id']
    psn = data['sessionParameters']['acs_server']
    url = f'https://{server}/admin/API/mnt/CoA/Reauth/{psn}/{mac}/0'
    try:
        r = s.get(url,verify=False)
        if (r.status_code == 200) and (
                xmltodict.parse(r.text)['remoteCoA']['results'] == 'true'):
            return True
    except:
        print(f'Error: \n{traceback.format_exc()}')
    return False


########################
# CoA Session Terminate
#   with Port Bounce
# NOT Compatible with VPN and Wireless endpoints
#   will only ReAuth for VPN/Wireless endpoints
# Returns True/False
def coa_bounce_by_ip(server,username,password,ip):
    s = requests.session()
    s.auth = (username,password)
    sess = get_sess_by_ip(server,username,password,ip)
    if not sess:
        return False
    data = xmltodict.parse(sess)
    mac = data['sessionParameters']['calling_station_id']
    psn = data['sessionParameters']['acs_server']
    url = f'https://{server}/admin/API/mnt/CoA/Disconnect/{psn}/{mac}/1'
    try:
        r = s.get(url,verify=False)
        if (r.status_code == 200) and (
                xmltodict.parse(r.text)['remoteCoA']['results'] == 'true'):
            return True
    except:
        print(f'Error: \n{traceback.format_exc()}')
    return False


########################
# CoA Session Terminate
#   with Port Bounce
# NOT Compatible with VPN and Wireless endpoints
#   will only ReAuth for VPN/Wireless endpoints
# Returns True/False
def coa_shut_by_ip(server,username,password,ip):
    s = requests.session()
    s.auth = (username,password)
    sess = get_sess_by_ip(server,username,password,ip)
    if not sess:
        return False
    data = xmltodict.parse(sess)
    mac = data['sessionParameters']['calling_station_id']
    psn = data['sessionParameters']['acs_server']
    url = f'https://{server}/admin/API/mnt/CoA/Disconnect/{psn}/{mac}/2'
    try:
        r = s.get(url,verify=False)
        if (r.status_code == 200) and (
                xmltodict.parse(r.text)['remoteCoA']['results'] == 'true'):
            return True
    except:
        print(f'Error: \n{traceback.format_exc()}')
    return False


########################
# CoA Session Terminate
# No Port Bounce or Shutdown
# Compatible with VPN and Wireless endpoints
# Returns True/False
def sess_del_by_ip(server,username,password,ip):
    s = requests.session()
    s.auth = (username,password)
    sess = get_sess_by_ip(server,username,password,ip)
    if not sess:
        return False
    data = xmltodict.parse(sess)
    sess_id = data['sessionParameters']['audit_session_id']
    url = f'https://{server}/admin/API/mnt/Session/Delete/SessionID/{sess_id}'
    try:
        r = s.delete(url,verify=False)
        if (r.status_code == 200) and (
                xmltodict.parse(r.text)['mnt-rest-result']['status'] == 'SUCCESSFUL'):
            return True
    except:
        print(f'Error: \n{traceback.format_exc()}')
    return False











