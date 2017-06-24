### This is a SIP registrar server, which provides registration function for ISM
#python registrar.py
#20-May 2017 - Version 1.0
#02-Jun 2017 - Version 1.1 - Fix some SIP errors and Diameter errors
#!/usr/bin/python

#from diameter import *
#from diameter.node import *
import hashlib
from libDiameter import *
import logging
import random
import re
import socket
import SocketServer
import string
import threading
import time

g_password = {"alice":"alice","bob":"bob"}#Statis password DB
g_reg_await_auth_delta = 1000#Miliseconds
g_reg_await_auth_start = 0
g_nonce = ""#A SipHandler Obj is created every new Register Request comming. New SipHandler Obj, in turn, generates new Nonce value
            #So it needs to use g_nonce to store Nonce value created by the first Register request, in the registration transaction
g_registrar = {}#Registration database to store all valided bindings
                #g_registrar[uri] = [contact, validity, profile]
g_server_name = "scscf-demo"#Without any DNS support

rx_addr = re.compile("sip:([^ ;>$]*)")
rx_authorization = re.compile("^Authorization: +\S{6} (.*)")
rx_ccontact = re.compile("^m:")
rx_contact = re.compile("^Contact:")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_content_length = re.compile("^Content-Length:")
rx_cto = re.compile("^t:")
rx_expires = re.compile("^Expires: (.*)$")
rx_kv= re.compile("([^=]*)=(.*)")
rx_maxforwards = re.compile("^Max-Forwards:")
rx_path = re.compile("^Path:")
rx_p_charging_vector = re.compile("^P-Charging-Vector:")
rx_p_visited_network_id = re.compile("^P-Visited-Network-ID:")
rx_register = re.compile("^REGISTER")
rx_require = re.compile("^Require:")
rx_tag = re.compile(";tag")
rx_to = re.compile("^To:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_useragent = re.compile("^User-Agent:")

class DiameterClient():
    def __init__(self):
        HOST, PORT = "localhost", 3868
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
        except Exception as e:
            logging.warning("Can not connect to server 3868")
            logging.warning("Exception is %s" % e)
    def __del__(self):
        self.sock.close()
    def send(self, data):
        self.sock.sendall(data)
    def recv(self, bufSize):
        return self.sock.recv(bufSize)

def generateNonce(n):
    s = "0123456789abcdef"
    length = len(s)
    nonce = ""
    for i in range(n):
        a = int(random.uniform(0,length))
        nonce += s[a]
    return nonce

def checkAuthorization(authorization, password, nonce):
    mhash = {}
    mlist = authorization.split(",")
    for elem in mlist:
        md = rx_kv.search(elem)
        if md:
            value = string.strip(md.group(2),'" ')
            key = string.strip(md.group(1))
            mhash[key] = value
    #TODO: need to check why sometimes mhash.has_key("nonce") returns False
    if mhash.has_key("nonce") and mhash["nonce"] != nonce:
        logging.warning("Incorrect nonce")
        logging.warning("UAE nonce: %s; SCSCF nonce: %s" % (mhash["nonce"],nonce))
        return False
    a1 = "%s:%s:%s" % (mhash["username"],mhash["realm"],password)
    a2 = "REGISTER:%s" % mhash["uri"]
    ha1 = hashlib.md5(a1).hexdigest()
    ha2 = hashlib.md5(a2).hexdigest()
    b = "%s:%s:%s:%s:%s:%s" % (ha1,nonce,mhash["nc"],mhash["cnonce"],mhash["qop"],ha2)
    expected = hashlib.md5(b).hexdigest()
    if expected == mhash["response"]:
        logging.debug("Authentication succeeded")
        return True
    return False

def checkRegAwaitAuth(uri):
    global g_registrar
    contact, validity, profile = g_registrar[uri]
    reg_await_auth_stop = time.time()*1000
    if g_reg_await_auth_start > reg_await_auth_stop - g_reg_await_auth_delta:
        return True
    else:
        del g_registrar[uri]
        return False

def padHex(i, l):
    hex_result = hex(i)[2:]#remove '0x'
    num_hex_chars = len(hex_result)
    extra_zeros = '0' * (l - num_hex_chars)
    return (hex_result if num_hex_chars == l else extra_zeros + hex_result if num_hex_chars < l else None)

class SipHandler(SocketServer.BaseRequestHandler):
    contact = ""
    domain = ""
    username = ""
    validity = 0
    
    def sendResponse(self, code):
        global g_nonce
        global g_registrar
        global g_server_name
        uri = ""
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            if line == "":
                break;
            if rx_maxforwards.search(line):
                pass#Bypass
            elif rx_useragent.search(line):
                pass
            elif rx_require.search(line):
                pass
            elif rx_p_charging_vector.search(line):
                pass
            elif rx_p_visited_network_id.search(line):
                pass
            elif rx_content_length.search(line):
                pass
            elif rx_contact.search(line):
                pass
            elif rx_expires.search(line):
                pass
            else:
                data.append(line)
                if rx_to.search(line) and not rx_tag.search(line):
                        data[index] = "%s%s" % (line,";tag=123456")
                index += 1
        if code == "401 Unauthorized":
            data.append('WWW-Authenticate: Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"' % (self.domain,g_nonce))
        if code == "200 OK":
            uri = "%s@%s" % (self.username,self.domain)
            if g_registrar.has_key(uri):
                contact, validity, profile = g_registrar[uri]
                expires = validity - int(time.time())
                data.append("P-Associated-URI: <sip:%s>" % uri)
                data.append("Contact: <sip:%s@%s>;expires=%s" % (self.username,contact,expires))
                logging.warning("uri: %s" % uri)
                logging.warning("contact: %s" % contact)
                logging.warning("expires: %s" % expires)
        data.append("Service-Route: <sip:orig@scscf.open-ims.test:6060;lr>")
        data.append("Allow: CANCEL")
        if code == "200 OK":
            data.append("P-Charging-Function-Addresses: ccf=pri_ccf_address")
        data.append("Server: %s") % g_server_name
        data.append("Content-Length: 0")
        data.append("")
        data.append("")
        text = string.join(data,"\r\n")
        self.socket.sendto(text,self.client_address)
        
    def processRegister(self):
        global g_registrar
        global g_nonce
        global g_reg_await_auth_start
        fromm = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        #1) Parsing data to get information from Request
        #-----------------------------------------------
        for line in self.data:
            #TODO: needs to bypass duplicated Register messages
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    self.username, self.domain = md.group(1), md.group(2)
                    fromm = "%s@%s" % (md.group(1),md.group(2))
            if rx_contact.search(line):
                md = rx_uri.search(line)
                if md:
                    self.contact = md.group(2)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)
                expires = int(header_expires)
            md = rx_authorization.search(line)
            if md:
                authorization= md.group(1)
                auth_index = index
            if not (rx_p_visited_network_id.search(line) and re.search(self.domain,line)):
                #P-Visited-Network-ID should be validated by I-CSCF
                pass
            index += 1
        
        #2) Authenticating
        #-----------------
        diameterClient = DiameterClient()
        LoadDictionary("dictDiameter.xml")
        if auth_index > 0:
            self.data.pop(auth_index)# Removing Authorization header for responses
        
        if not g_registrar.has_key(fromm):
            g_nonce = generateNonce(32)
            #TODO: needs to avoid sending CER before sending MAR and SAR
            CER = "010000dc800001010000000076ead7b1239ad9d0000001084000001b73637363662e6f70656e2d696d732e746573740000000128400000156f70656e2d696d732e74657374000000000001014000000e00017f00000100000000010a4000000c000028af0000010d00000015434469616d657465725065657200000000000104400000200000010a4000000c000028af000001024000000c0100000000000104400000200000010a4000000c0000118b000001024000000c0100000000000104400000200000010a4000000c000032db000001024000000c01000000"
            diameterClient.send(CER.decode("hex"))#Sending CER at the beginning
            msg = diameterClient.recv(4096)
            MAR_REQ_avps = []
            session_id = "%s,%s" % (self.domain, generateNonce(32))
            MAR_REQ_avps.append(encodeAVP("Session-Id", "%s" % session_id))
            MAR_REQ_avps.append("000001084000001b73637363662e6f70656e2d696d732e74657374")#Origin-Host
            MAR_REQ_avps.append("00000128400000156f70656e2d696d732e74657374")#Origin-Realm
            MAR_REQ_avps.append("0000011b400000156f70656e2d696d732e74657374")#Destination-Realm
            MAR_REQ_avps.append("00000104400000200000010a4000000c000028af000001024000000c01000000")#Vendor-Specific-Application-Id
            MAR_REQ_avps.append("000001154000000c00000001")#Auth-Session-State
            #TODO: needs to solve problem with group AVPs
            #MAR_REQ_avps.append(encodeAVP("Public-Identity",[encodeAVP("Vendor-Id", dictVENDORid2code("TGPP")),encodeAVP("Public-Identity", "%s" % fromm)]))
            fromm_hex = "sip:%s" % fromm
            fromm_hex = fromm_hex.encode("hex")
            avp_length = (4+1+3+4) + len(fromm_hex)/2
            avp_length_hex = padHex(avp_length, 6)
            MAR_REQ_avps.append("00000259c0%s000028af%s" % (avp_length_hex,fromm_hex))
            MAR_REQ_avps.append(encodeAVP("User-Name", "%s" % fromm))
            MAR_REQ_avps.append("0000025fc0000010000028af00000001")#SIP-Number-Auth-Items
            MAR_REQ_avps.append("00000264c0000024000028af00000260c0000016000028af4469676573742d4d44350000")#SIP-Auth-Data-Item
            #MAR_REQ_avps.append("0000025ac0000028000028af7369703a73637363662e6f70656e2d696d732e746573743a36303630")#Server-Name
            MAR_REQ_avps.append(encodeAVP("Server-Name", "%s" % g_server_name))
            MAR_REQ = HDRItem()#Creating an empty header
            MAR_REQ.cmd = 303#Setting command code Multimedia-AuthRequest
            MAR_REQ.appId = 16777216#Setting Application ID
            MAR_REQ.flags = 0xc0
            initializeHops(MAR_REQ)
            msg = createReq(MAR_REQ, MAR_REQ_avps)
            diameterClient.send(msg.decode("hex"))#Sending MAR
            msg = diameterClient.recv(4096)
            MAR_RES = HDRItem()
            stripHdr(MAR_RES,msg.encode("hex"))
            MAR_RES_avps = splitMsgAVPs(MAR_RES.msg)
            sip_auth_data_item_avp = MAR_RES_avps[len(MAR_RES_avps)-2]#SIP-Auth-Data-Item
            (removed_bytes,msg)=chop_msg(sip_auth_data_item_avp,8)#Removing Code of SIP-Auth-Data-Item (4 bytes)
            (removed_bytes,msg)=chop_msg(msg,2)#Removing Flag of SIP-Auth-Data-Item (1 byte)
            (removed_bytes,msg)=chop_msg(msg,6)#Removing Length of SIP-Auth-Data-Item (3 bytes)
            (removed_bytes,msg)=chop_msg(msg,8)#Removing Vendor Id of SIP-Auth-Data-Item (4 bytes)
            (removed_bytes,msg)=chop_msg(msg,8)#Removing Code of SIP-Item-Number (4 bytes)
            (removed_bytes,msg)=chop_msg(msg,2)#Removing Flag of SIP-Item-Number (1 byte)
            (avp_length,msg)=chop_msg(msg,6)#Removing Length of SIP-Item-Number (3 bytes)
            avp_padding_length = calc_padding(int(avp_length, 16))
            (removed_bytes,msg)=chop_msg(msg,(avp_padding_length-4-1-3)*2)#Removing remained bytes of SIP-Item-Number
            (removed_bytes,msg)=chop_msg(msg,8)#Removing Code of SIP-Authentication-Scheme (4 bytes)
            (removed_bytes,msg)=chop_msg(msg,2)#Removing Flag of SIP-Authentication-Scheme (1 byte)
            (avp_length,msg)=chop_msg(msg,6)#Removing Length of SIP-Authentication-Scheme (3 bytes)
            avp_padding_length = calc_padding(int(avp_length, 16))
            (removed_bytes,msg)=chop_msg(msg,(avp_padding_length-4-1-3)*2)#Removing remained bytes of SIP-Authentication-Scheme
            (removed_bytes,msg)=chop_msg(msg,8)#Removing Code of SIP-Authenticate (4 bytes)
            (removed_bytes,msg)=chop_msg(msg,2)#Removing Flag of SIP-Authenticate (1 byte)
            (avp_length,msg)=chop_msg(msg,6)#Removing Length of SIP-Authenticate (3 bytes)
            avp_padding_length = calc_padding(int(avp_length, 16))
            (removed_bytes,msg)=chop_msg(msg,(avp_padding_length-4-1-3)*2)#Removing remained bytes of SIP-Authenticate
            (removed_bytes,sip_authenticate)=chop_msg(removed_bytes,8)#Removing Vendor Id from remained bytes of SIP-Authenticate  
            logging.warning(sip_authenticate)
            self.sendResponse("401 Unauthorized")
            g_reg_await_auth_start = time.time()*1000
            if len(header_expires) > 0:
                self.validity = int(g_reg_await_auth_start/1000) + expires
            g_registrar[fromm] = [self.contact,self.validity,""]#Updating DB
            logging.warning("fromm: %s" % fromm)
            logging.warning("contact: %s" % self.contact)
            logging.warning("validity: %s" % self.validity)
        else:
            if expires == 0:#De-Registration
                #TODO: May need to send Diameter Registration-TerminationRequest 304
                del g_registrar[fromm]
                self.sendResponse("200 OK")
            else:
                if not g_password.has_key(self.username) and (not checkAuthorization(authorization,g_password[self.username],g_nonce) or not checkRegAwaitAuth(fromm)):
                    self.sendResponse("403 Forbidden")
                else:
                    CER = "010000dc800001010000000076ead7b1239ad9d0000001084000001b73637363662e6f70656e2d696d732e746573740000000128400000156f70656e2d696d732e74657374000000000001014000000e00017f00000100000000010a4000000c000028af0000010d00000015434469616d657465725065657200000000000104400000200000010a4000000c000028af000001024000000c0100000000000104400000200000010a4000000c0000118b000001024000000c0100000000000104400000200000010a4000000c000032db000001024000000c01000000"
                    diameterClient.send(CER.decode("hex"))#Sending CER at the beginning
                    msg = diameterClient.recv(4096)
                    SAR_REQ_avps = []
                    SAR_REQ_avps.append("000001074000002873637363662e6f70656e2d696d732e746573743b3234323832393731373b3332")#Session-Id
                    SAR_REQ_avps.append("000001084000001b73637363662e6f70656e2d696d732e74657374")#Origin-Host
                    SAR_REQ_avps.append("00000128400000156f70656e2d696d732e74657374")#Origin-Realm
                    SAR_REQ_avps.append("0000011b400000156f70656e2d696d732e74657374")#Destination-Realm
                    SAR_REQ_avps.append("00000104400000200000010a4000000c000028af000001024000000c01000000")#Vendor-Specific-Application-Id
                    SAR_REQ_avps.append("000001154000000c00000001")#Auth-Session-State
                    #TODO: needs to solve problem with group AVPs
                    #SAR_REQ_avps.append(encodeAVP("Public-Identity",[encodeAVP("Vendor-Id", "10415"),encodeAVP("Public-Identity", "%s" % fromm)]))
                    fromm_hex = "sip:%s" % fromm
                    fromm_hex = fromm_hex.encode("hex")
                    avp_length = (4+1+3+4) + len(fromm_hex)/2
                    avp_length_hex = padHex(avp_length, 6)
                    SAR_REQ_avps.append("00000259c0%s000028af%s" % (avp_length_hex,fromm_hex))
                    SAR_REQ_avps.append(encodeAVP("User-Name", "%s" % fromm))
                    SAR_REQ_avps.append("0000025ac0000028000028af7369703a73637363662e6f70656e2d696d732e746573743a36303630")#Server-Name
                    SAR_REQ_avps.append("00000266c0000010000028af00000001")#Server-Assignment-Type
                    SAR_REQ_avps.append("00000270c0000010000028af00000000")#User-Data-Already-Available
                    SAR_REQ = HDRItem()#Creating an empty header
                    SAR_REQ.cmd = 301#Setting command code Server-AssignmentRequest
                    SAR_REQ.appId = 16777216#Setting Application ID
                    SAR_REQ.flags = 0xc0
                    initializeHops(SAR_REQ)
                    msg = createReq(SAR_REQ, SAR_REQ_avps)
                    diameterClient.send(msg.decode("hex"))#Sending SAR
                    msg = diameterClient.recv(4096)
                    SAR_RES = HDRItem()
                    stripHdr(SAR_RES,msg.encode("hex"))
                    SAR_RES_avps = splitMsgAVPs(SAR_RES.msg)
                    user_data_avp = SAR_RES_avps[len(SAR_RES_avps)-3]#User-Data
                    (removed_bytes,msg)=chop_msg(user_data_avp,8)#Removing Code of User-Data (4 bytes)
                    (removed_bytes,msg)=chop_msg(msg,2)#Removing Flag of User-Data (1 byte)
                    (avp_length,msg)=chop_msg(msg,6)#Removing Length of User-Data (3 bytes)
                    avp_padding_length = calc_padding(int(avp_length, 16))
                    (removed_bytes,msg)=chop_msg(msg,(avp_padding_length-4-1-3)*2)#Removing remained bytes of User-Data
                    (removed_bytes,profile)=chop_msg(removed_bytes,8)#Removing Vendor Id from remained bytes of User-Data
                    logging.info(profile.decode("hex"))
                    self.sendResponse("200 OK")
                    g_registrar[fromm][2] = profile
        return

    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                self.processRegister()
            else:
                logging.warning("Only REGISTER request is processed")
        else:
            logging.error("Request is corrupted")
       
    def handle(self):
        data = self.request[0]
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        self.processRequest()

if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s:%(funcName)s:%(lineno)d:%(message)s', level=logging.WARNING)
    HOST, PORT = "localhost", 6060
    server = SocketServer.UDPServer((HOST, PORT), SipHandler)
    server.serve_forever()
