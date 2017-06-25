''' This URL shortener
    receives a list of URLs, in a file named "urls", and returns a list of shortened URLs, in a file named "shortened_urls", ex: "http://en.wikipedia.org/wiki/URL_shortening" is shortened to "http://localhost/a_random_string"
    stores shortened URLs to a Database
    starts a http server onlocal host
    redirects the request of "http://localhost/a_random_string" to "http://en.wikipedia.org/wiki/URL_shortening"
'''
#python urlShortener.py
#23-June 2017 - Version 1.0
#!/usr/bin/python

import sys
if sys.version_info[0] >= 3:
    print("This app does not support Python 3.x yet")
    exit() 

try:
    from bottle import redirect, route, run, abort
except Exception as e:
    print "pip install bottle"
import hashlib
import logging
import random
import re
import urllib2

g_url = {}#This contains full name and short name of a URL
          #{"full":"http://en.wikipedia.org/wiki/URL_shortening", "short":"http://lin.ks/a_random_string"}
g_urls = {}#This is a set of g_url s
           #{hashlib.md5(g_url["short"]).hexdigest(), g_url}
G_SHORT_DOMAIN_NAME = "localhost"
G_PORT = 80
G_INPUT_FILE_NAME = "full"
G_OUTPUT_FILE_NAME = "short"

def generateRandomStr(l):
    '''
    This function generates "a_randrom_string"
    Input: l - expected lenght of "a_random_string"
    Output: "a_random_string"
    '''
    s = "0123456789abcdef"
    length = len(s)
    a_random_str = ""
    for i in range(l):
        a = int(random.uniform(0,length))
        a_random_str += s[a]
    return a_random_str

def validateUrl(url):
    '''
    This function validate an URL to make sure it has correct form
    Input: url
    Output: True/False
    '''
    try:
        ret = urllib2.urlopen(url)
        if ret.code == 200:
            return True
        else:
            return False
    except Exception as e:
        logging.error(e)
        return False
    return False

def shortUrl(url):
    '''
    This function creates "http://localhost/a_random_string" from "http://en.wikipedia.org/wiki/URL_shortening"
    Input: Original URL
    Ouput: Shortened URL
    '''
    global G_SHORT_DOMAIN_NAME
    global G_PORT
    short_url = ''
    if not G_PORT == 80:
        short_url = "http://%s:%d/" % (G_SHORT_DOMAIN_NAME, G_PORT)
    else:
        short_url = "http://%s/" % (G_SHORT_DOMAIN_NAME)
    l = 0
    a_random_str = ""
    if validateUrl(url):
        if len(url) < (len(short_url)+2):
            l = 1
        else:
            l = (len(url) - len(short_url))/2
        a_random_str = generateRandomStr(l)
        short_url = short_url + a_random_str
        logging.warning(short_url)
        return short_url
    else:
        return ""

@route('/<path:re:.*>')
def redirectAll(path):
    '''
    This function looks for "full url" in the Database and redirects requesst to it
    Input: shortened "url"  
    '''
    global g_urls
    global G_SHORT_DOMAIN_NAME
    global G_PORT
    short_url = ''
    if not G_PORT == 80:
        short_url = "http://%s:%d" % (G_SHORT_DOMAIN_NAME, G_PORT)
    else:
        short_url = "http://%s" % (G_SHORT_DOMAIN_NAME)
    short_url = '%s/%s' % (short_url,path)
    h = hashlib.md5(short_url).hexdigest()
    if g_urls.has_key(h):
        f = re.sub('\n', '', g_urls[h]['full'])
        redirect(f)
    else:
        abort(404, '%s is not in the Database' % short_url)

def printDatabase():
    global g_urls
    for k in g_urls:
        logging.warning("%s - %s - %s" % (h, g_urls[h]['full'], g_urls[h]['short']))

if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s:%(funcName)s:%(lineno)d:%(message)s', level=logging.WARNING)
    try:
        with open(G_INPUT_FILE_NAME, "r") as input_file:
            with open(G_OUTPUT_FILE_NAME, "w") as output_file:
                for url in input_file:
                    shortened_url = shortUrl(url)
                    output_file.write('%s\n' % shortened_url)
                    h = hashlib.md5(shortened_url).hexdigest()
                    g_urls[h] = {}#Update the Database
                    g_urls[h]['full'] = url
                    g_urls[h]['short'] = shortened_url
                    logging.warning("%s - %s - %s" % (h, g_urls[h]['full'], g_urls[h]['short']))
        printDatabase()
        run(host=G_SHORT_DOMAIN_NAME, port=G_PORT, debug=True)#Start a HTTP server
    except Exception as e:
        logging.error(e)
    pass
