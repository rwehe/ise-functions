import re
import random
import requests
import xml.dom.minidom as dom
import xml.etree.ElementTree as etree


########################
# Random Password Generator
# Returns 14 character string
def Random_Password(num=14):
    Random_Pass = ''
    while len(Random_Pass) < num:
        char = 'abcdefghijklmnopqrstuvwxyz'
        CHAR = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        NUM = '1234567890'
        sym = '!@#$%&()[]{}'

        Random_Pass += random.choice(char)
        Random_Pass += random.choice(NUM)
        Random_Pass += random.choice(CHAR)
        Random_Pass += random.choice(sym)

    return Random_Pass

########################
# Validate MAC Address
# Returns True/False
def Validate_MAC(mac_addr):
    mac_addr = mac_addr.lower().strip().replace('-','').replace(':','').replace('.','')
    # Validate MAC Address using RegEx
    pattern = r'^[a-f0-9]{12}$'
    if not re.match(pattern, mac_addr):
        return False
    else:
        return True

########################
# ISE Auth Test Function
# If Authentication Fails, Returns True
# Else Returns False
# Writes results to file
def ISE_AUTH_TEST(server,username,password,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml")
    headers = {'Accept': accept_header}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/networkdevice"
    try:
        r = None
        outFile.write("Testing Authentication to "+server+"\n")
        print("Testing Authentication to "+server+"\n")
        # REST call with SSL verification turned off:
        r = requests.post(url=url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 401):
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
            r.close()
            return True
        else:
            outFile.write("Authentication Successful\n")
            print("Authentication Successful for\n")
            r.close()
            return False
    except:
        outFile.write("Connection Test Error -->  "+username+"\n"+server+"\n")
        r.close()
        return False

########################
# ISE POST Network Device Function
# Returns Response Text
# Writes results to file
def ISE_POST_DEV(server,post_data,username,password,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml")
    content_type = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml; charset=utf-8")
    headers = {'Accept': accept_header,'Content-Type': content_type}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/networkdevice"
    try:
        r = None
        print("Posting to --> "+url+"\n")
        # REST call with SSL verification turned off:
        r = requests.post(url, data=(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 201):
            r.close()
            # Save To File
            outFile.write("POST successful\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            r.raise_for_status()
            outFile.write("Error occurred in POST...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        if "Already Exist" in resp or "overlapping" in resp.lower():
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Device Already Exists...\n"+(xml.toprettyxml())+"\n")
        elif "The specified NDG cannot be found in DB" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Device location NDG cannot be found, creating NDG...\n")
            if r : r.close()
        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error in connection...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()

    # Return
    return resp


########################
# ISE PUT Network Device Function
# Returns Response Text
# Writes results to file
def ISE_PUT_DEV(server,post_data,username,password,outFile,ID):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml")
    content_type = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml; charset=utf-8")
    headers = {'Accept': accept_header,'Content-Type': content_type}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/networkdevice/" + ID
    try:
        r = None
        print("Posting to --> "+url+"\n")
        # REST call with SSL verification turned off:
        r = requests.put(url, data=(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 201):
            r.close()
            # Save To File
            outFile.write("POST successful\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            r.raise_for_status()
            outFile.write("Error occurred in POST...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        if "Already Exist" in resp or "overlapping" in resp.lower():
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Device Already Exists...\n"+(xml.toprettyxml())+"\n")
        elif "The specified NDG cannot be found in DB" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Device location NDG cannot be found, creating NDG...\n")
            if r : r.close()
        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error in connection...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()

    # Return
    return resp


############################
# ISE Network Device GET Function
# Filter by IP or NAME
# IP Address Required, ID Optional
# Returns Response Text
def ISE_GET_DEV(server,username,password,dev,ID=None,Filter='IP'):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml")
    accept_search = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header ,'Accept-Search-Result': accept_search}

    ########################
    # Define URLs to perform API POST
    #
    if ID != None:
        url = "https://"+server+":9060/ers/config/networkdevice/"+ ID
    elif Filter == 'IP':
        url = "https://"+server+":9060/ers/config/networkdevice/?filter=ipaddress.EQ."+ dev
    elif Filter == 'NAME':
        url = "https://"+server+":9060/ers/config/networkdevice/?filter=name.CONTAINS."+ dev
    try:
        r = None
        print("Getting Device ID from: "+url)
        # REST call with SSL verification turned on:
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            # Save To File
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp

    # End
    finally:
        r.close()
    return resp



############################
# ISE DELETE Network Device Function
# 'devID' is UUID for Network Device
# Writes results to file
def ISE_DELETE_DEV(server,username,password,devID,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.network.networkdevice.1.1+xml")
    headers = {'Accept': accept_header}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/networkdevice/"+devID
    try:
        r = None
        print("Deleting Device from: "+url)
        # REST call with SSL verification turned on:
        r = requests.delete(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 204):
            # Save To File
            print('Device Deleted Successfully\n')
            #xml = dom.parseString(resp)
            r.close()
            outFile.write("Network Device Deleted Successfully\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            print('Error Deleting Endpoint\n')
            r.raise_for_status()
            outFile.write("Error Deleting Endpoint...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        r.close()
        xml = dom.parseString(resp)
        print('Error Deleting Endpoint\n')
        outFile.write("Error Deleting Endpoint...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()
    return resp





########################
# ISE POST NDG Function
# Returns Response Text
# Writes results to file
def ISE_POST_NDG(server,post_data,username,password,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.network.networkdevicegroup.1.0+xml")
    content_type = ("application/vnd.com.cisco.ise.network.networkdevicegroup.1.0+xml; charset=utf-8")
    headers = {'Accept': accept_header,'Content-Type': content_type}
    # Request Headers

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/networkdevicegroup"
    try:
        print("Posting to --> "+url+"\n")
        r = requests.post(url, data=(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        ##TEST PRINT
        #print(resp)
        if (status_code == 201):
            r.close()
            # Save To File
            outFile.write("Location NDG Successfully Created...\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            r.raise_for_status()
            outFile.write("Error occurred in POST...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        if "Already Exist" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("NDG Already Exists...\n"+(xml.toprettyxml())+"\n")

        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error in connection...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()

    return resp




########################
# ISE POST Endpoint Function
# Writes results to file
# Returns Response Text
def ISE_POST_MAC(server,post_data,username,password,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.endpoint.1.1+xml")
    content_type = ("application/vnd.com.cisco.ise.identity.endpoint.1.1+xml; charset=utf-8")
    headers = {'Accept': accept_header,'Content-Type': content_type}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/endpoint"
    try:
        r = None
        print("Creating Endpoint --> "+url+"\n")
        outFile.write("Creating Endpoint\n")
        # REST call with SSL verification turned off:
        r = requests.post(url, data=(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), timeout=5, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 201):
            r.close()
            # Save To File
            outFile.write("Endpoint Successfully Created\n")
            return "Endpoint Successfully Created"
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            r.raise_for_status()
            outFile.write("Error occurred in POST...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        if "Failed to update endpoint" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Endpoint Already exists\n")
            if r : r.close()
        elif "Unable to create the endpoint" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Endpoint Already exists\n")
            if r : r.close()
        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error Creating Endpoint...\n"+(xml.toprettyxml())+"\n")
    except:
        return

    # End
    finally:
        if r : r.close()

    # Return
    return resp

############################
# ISE GET Endpoint Function
# MAC filter Required, ID Optional
# Returns Response Text
def ISE_GET_MAC(server,username,password,mac_addr,ID=None):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.endpoint.1.1+xml")
    accept_search = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header ,'Accept-Search-Result': accept_search}

    ########################
    # Define URLs to perform API POST
    #
    if ID != None:
        url = "https://"+server+":9060/ers/config/endpoint/"+ ID
    else:
        url = "https://"+server+":9060/ers/config/endpoint/?filter=mac.EQ."+ mac_addr

    try:
        r = None
        print("Getting Endpoint ID from: "+url)
        # REST call with SSL verification turned on:
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            # Save To File
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp

    # End
    finally:
        if r : r.close()
    return resp



############################
# ISE DELETE Endpoint Function
# Writes results to file
# Returns Response Text
def ISE_DELETE_MAC(server,username,password,endpointID,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.endpoint.1.1+xml")
    headers = {'Accept': accept_header}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/endpoint/"+endpointID
    try:
        r = None
        print("Deleting Endpoint from: "+url)
        # REST call with SSL verification turned on:
        r = requests.delete(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 204):
            r.close()
            # Save To File
            print('Endpoint Deleted Successfully\n')
            outFile.write("Endpoint Deleted Successfully\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            print('Error Deleting Ednpoint\n')
            r.raise_for_status()
            outFile.write("Error Deleting Endpoint...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        r.close()
        xml = dom.parseString(resp)
        print('Error Deleting Endpoint\n')
        outFile.write("Error Deleting Endpoint...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()
    return resp



########################
# ISE POST Internal User Function
# Writes results to file
# Returns Response Text
def ISE_POST_USER(server,post_data,username,password,outFile):
    ########################
    # Define Headers
    #
    accept_header = ('application/vnd.com.cisco.ise.identity.internaluser.1.2+xml')
    content_type = ('application/vnd.com.cisco.ise.identity.internaluser.1.2+xml; charset=utf-8')
    headers = {'Accept': accept_header,'Content-Type': content_type}

    ########################
    # Define URLs to perform API POST
    #
    url = 'https://'+server+':9060/ers/config/internaluser'
    try:
        r = None
        print("Creating User --> "+url+"\n")
        outFile.write("Creating User\n")
        # REST call with SSL verification turned off:
        r = requests.post(url, data=(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 201):
            r.close()
            # Save To File
            outFile.write("User Successfully Created\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            r.raise_for_status()
            outFile.write("Error occurred in POST...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        if "Failed to update user" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("User Already exists\n")
            if r : r.close()
        elif "Unable to create the user" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("User Already exists\n")
            if r : r.close()
        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error Creating User...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()

    # Return
    return resp



############################
# ISE GET Internal User Function
# Email filter Optional
# Returns Response Text
def ISE_GET_USER(server,username,password,email=None,name=None):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.internaluser.1.2+xml")
    accept_search_header = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header,'Accept-Search-Result': accept_search_header}

    ########################
    # Define URLs to perform API POST
    #
    if email != None:
        url = 'https://'+server+':9060/ers/config/internaluser?filter=email.EQ.'+ email
    elif name != None:
        url = 'https://'+server+':9060/ers/config/internaluser?filter=name.EQ.'+ name
    else:
        url = 'https://'+server+':9060/ers/config/internaluser'

    try:
        r = None
        print("Getting User ID from: "+url)
        # REST call with SSL verification turned on:
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            # Save To File
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp

    # End
    finally:
        if r : r.close()
    return resp


############################
# ISE DELETE User Function
# Writes results to file
# Returns Response Text
def ISE_DELETE_USER(server,username,password,userID,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.internaluser.1.2+xml")
    headers = {'Accept': accept_header}

    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/internaluser/"+userID
    try:
        r = None
        print("Deleting User from: "+url)
        # REST call with SSL verification turned on:
        r = requests.delete(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 204):
            r.close()
            # Save To File
            print('User Deleted Successfully\n')
            outFile.write("User Deleted Successfully\n")
        elif (status_code == 401):
            r.close()
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            print('Error Deleting User\n')
            r.raise_for_status()
            outFile.write("Error Deleting User...\n"+(xml.toprettyxml())+"\n")
    except requests.exceptions.HTTPError as err:
        r.close()
        xml = dom.parseString(resp)
        print('Error Deleting User\n')
        outFile.write("Error Deleting User...\n"+(xml.toprettyxml())+"\n")

    # End
    finally:
        if r : r.close()
    return resp


############################
# ISE GET User Identity Group Function
# Name or ID Optional
# Returns Response Text
def ISE_GET_USER_GROUP(server,username,password,name=None,ID=None):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.identitygroup.1.0+xml")
    accept_search_header = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header,'Accept-Search-Result': accept_search_header}

    ########################
    # Define URLs to perform API POST
    #
    if ID != None:
        url = "https://"+server+":9060/ers/config/identitygroup/"+ ID
    elif name != None:
        url = "https://"+server+":9060/ers/config/identitygroup/?filter=name.EQ."+ name
    else:
        url = "https://"+server+":9060/ers/config/identitygroup"


    try:
        r = None
        print("Getting User Identity Group ID from: "+url)
        # REST call with SSL verification turned on:
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            # Save To File
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp

    # End
    finally:
        if r : r.close()
    return resp


########################
# ISE POST Guest User Function
# Writes results to file
# Returns Response Text
def ISE_POST_GUEST_USER(server,post_data,username,password,outFile):
    ########################
    # Define Headers
    #
    accept_header = ('application/vnd.com.cisco.ise.identity.guestuser.2.0+xml')
    content_type = ('application/vnd.com.cisco.ise.identity.guestuser.2.0+xml; charset=utf-8')
    headers = {'Accept': accept_header,'Content-Type': content_type}
    ########################
    # Define URLs to perform API POST
    #
    url = 'https://'+server+':9060/ers/config/guestuser'
    try:
        r = None
        print("Creating Guest User --> "+url+"\n")
        r = requests.post(url, data=(post_data), headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 201):
            # Save To File
            outFile.write("User Successfully Created\n")
            print('Guest User Created Successfully\n')
            r.close()
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error occurred in POST...\n"+(xml.toprettyxml())+"\n")
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        if "User with same username already exists" in resp:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("User Already exists\n")
            if r : r.close()
        else:
            r.close()
            xml = dom.parseString(resp)
            outFile.write("Error Creating User...\n"+(xml.toprettyxml())+"\n")
            if r : r.close()
    finally:
        if r : r.close()
    return resp



############################
# ISE GET Guest User Function
# Email filter Optional
# Returns Response Text
def ISE_GET_GUEST_USER(server,username,password,**kwargs):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.guestuser.2.0+xml")
    accept_search_header = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header,'Accept-Search-Result': accept_search_header}

    ########################
    # Define URLs to perform API POST
    #
    if 'email' in kwargs:
        email = kwargs['email']
        url = 'https://'+server+':9060/ers/config/guestuser?filter=emailAddress.EQ.'+ email
    elif 'name' in kwargs:
        name = kwargs['name']
        url = 'https://'+server+':9060/ers/config/guestuser/name/'+ name
    elif 'ID' in kwargs:
        ID = kwargs['ID']
        url = 'https://'+server+':9060/ers/config/guestuser/'+ ID
    else:
        url = 'https://'+server+':9060/ers/config/guestuser'
    try:
        r = None
        print("Getting Guest User from: "+url)
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp
    finally:
        if r : r.close()
    return resp


############################
# ISE DELETE Guest User Function
# Writes results to file
# Returns Response Text
def ISE_DELETE_GUEST_USER(server,username,password,userID,outFile):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.guestuser.2.0+xml")
    headers = {'Accept': accept_header}
    ########################
    # Define URLs to perform API POST
    #
    url = "https://"+server+":9060/ers/config/guestuser/"+userID
    try:
        r = None
        print("Deleting Guest User from: "+url)
        r = requests.delete(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 204):
            r.close()
            # Save To File
            print('Guest User Deleted Successfully\n')
            outFile.write("User Deleted Successfully\n")
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
            outFile.write("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            xml = dom.parseString(resp)
            print('Error Deleting Guest User\n')
            outFile.write("Error Deleting User...\n"+(xml.toprettyxml())+"\n")
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        xml = dom.parseString(resp)
        print('Error Deleting Guest User\n')
        outFile.write("Error Deleting User...\n"+(xml.toprettyxml())+"\n")
    finally:
        if r : r.close()
    return resp





############################
# ISE GET Endpoint Identity Group Function
# Name or ID Optional
# Returns Response Text
def ISE_GET_GROUP(server,username,password,name=None,ID=None):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml")
    accept_search_header = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header,'Accept-Search-Result': accept_search_header}

    ########################
    # Define URLs to perform API POST
    #
    if ID != None:
        url = "https://"+server+":9060/ers/config/endpointgroup/"+ ID
    elif name != None:
        url = "https://"+server+":9060/ers/config/endpointgroup/?filter=name.EQ."+ name
    else:
        url = "https://"+server+":9060/ers/config/endpointgroup"


    try:
        r = None
        print("Getting Endpoint Identity Group ID from: "+url)
        # REST call with SSL verification turned on:
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            # Save To File
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp

    # End
    finally:
        if r : r.close()
    return resp



############################
# ISE GET Endpoint Profile Function
# Name or ID optional
# Returns Response Text
def ISE_GET_PROFILE(server,username,password,name=None,ID=None):
    ########################
    # Define Headers
    #
    accept_header = ("application/vnd.com.cisco.ise.identity.profilerprofile.1.0+xml")
    accept_search_header = ("application/vnd.com.cisco.ise.ers.searchresult.2.0+xml")
    headers = {'Accept': accept_header,'Accept-Search-Result': accept_search_header}

    ########################
    # Define URLs to perform API POST
    #
    if ID != None:
        url = "https://"+server+":9060/ers/config/profilerprofile/"+ ID
    elif name != None:
        url = "https://"+server+":9060/ers/config/profilerprofile/?filter=name.EQ."+ name
    else:
        url = "https://"+server+":9060/ers/config/profilerprofile"

    try:
        r = None
        print("Getting Endpoint ID from: "+url)
        # REST call with SSL verification turned on:
        r = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            r.close()
            # Save To File
            xml = dom.parseString(resp)
        elif (status_code == 401):
            r.close()
            print("Authentication Failure -->  "+username+"\n"+server+"\n")
        else:
            r.close()
            r.raise_for_status()
    except requests.exceptions.HTTPError as err:
        r.close()
        print(resp)
        return resp

    # End
    finally:
        if r : r.close()
    return resp

