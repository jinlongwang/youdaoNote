#coding=utf-8
"""
该文件用于封装有道云笔记的API
"""
import cookielib

__author__ = 'jinlong'

try:
    import json
except ImportError:
    import simplejson as json

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from hashlib import sha1
import hmac
import binascii
import random
import httplib
from urllib import urlencode
import gzip, time, hmac, base64, hashlib, urllib, urllib2, logging, mimetypes

class ApiError(StandardError):
      '''
      raise APIError if got failed json message.
      '''
      def __init__(self, error_code, error):
        self.error_code = error_code
        self.error = error
        StandardError.__init__(self, error)

      def __str__(self):
        return 'APIError: %s: %s' % (self.error_code, self.error)


class Util():
    """
    请求的工具类
    """
    @staticmethod
    def addHeaderHttp(url,method,header):
        pass

    @staticmethod
    def callHttp(baseUrl,url,method,value_dic={},header=None):
        #print url,method,value_dic,header
        baseUrl = baseUrl.split("//")[1]
        value_dic = urllib.urlencode(value_dic)
        if method == "GET":
            if value_dic:
                url = url+"?"+value_dic
        #print value_dic
        #print url
        headers={}
        if header:
           headers = {"Authorization": 'OAuth '+header}
        conn = httplib.HTTPConnection(baseUrl)
        conn.request(method, url, "", headers)
        httpres = conn.getresponse()
        if httpres.status != 200:
            errorJson = eval(httpres.read())
            raise ApiError(errorJson.get('error'),errorJson.get('message'))
        return httpres.read()

        #print httpres.read()
        # if method == 'GET':
        #
        #     if value_dic:
        #         url_values = urllib.urlencode(value_dic)
        #         full_url = url + '?' + url_values
        #     else:
        #         full_url = url
        #     print full_url
        #     if header:
        #        req = urllib2.Request(url)
        #        req.add_header('Authorization', 'OAuth '+header)
        #        data = urllib2.urlopen(req)
        #     else:
        #        data = urllib2.urlopen(full_url)
        #     return data.read()
        #
        # if method == 'POST':
        #         print url
        #         #cj = cookielib.CookieJar()
        #         opener = urllib2.build_opener()
        #         urllib2.install_opener(opener)
        #         req = urllib2.Request(url, urllib.urlencode(value_dic))
        #         req.add_header("Content-Type","application/x-www-form-urlencoded")
        #         req.add_header("Authorization",'OAuth '+header)
        #         #req.add_header("User-Agent","Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)")
        #         print req.headers,'-------------'
        #         data = urllib2.urlopen(req)
        #
        #         return data.read()

    @staticmethod
    def sign_request(key,base_string):
        # If you dont have a token yet, the key should be only "CONSUMER_SECRET&"
        #key = "CONSUMER_SECRET&TOKEN_SECRET"
        # The Base String as specified here:
        #raw = "BASE_STRING" # as specified by oauth
        hashed = hmac.new(key, base_string, sha1)
        # The signature
        final_sign =  binascii.b2a_base64(hashed.digest())[:-1]
        print '---------',final_sign,'-----'
        return  Util.special_replace(final_sign)

    @staticmethod
    def getBaseSignString(method,httpUrl,httpType,**kw):
        """
        计算签名
        :param method:GET,POST
        :param httpUrl:http,https
        :param httpType: 1 , 2
        :param kw: 字典参数
        """
        finalUrl=""
        try:
            urlPort = httpUrl.split(":")[2].split('/')[0]
            if httpType == 1:
                if urlPort == '80':
                    finalUrl = httpUrl.replace(":80","")
            else:
                if urlPort == '443':
                    finalUrl = httpUrl.replace(":443","")
        except:
            finalUrl = httpUrl
        sign_string = method+"&"+Util.special_replace(finalUrl)
        #1.升序排列
        sortSeq = sorted(kw.iteritems(),key=lambda key:key[0])
        #2.key与value之间用=链接
        seq_list = []
        for seq in sortSeq:
            dicString = str(seq[0])+"="+str(seq[1])
            seq_list.append(dicString)
        seq_string = '&'.join(seq_list)

        seq_string = Util.special_replace(seq_string)
        print 'basestring:-------', sign_string+'&'+seq_string, '--------'
        return sign_string+'&'+seq_string

    @staticmethod
    def getSignNameKey(ConsumerSecret,TokenSecret=None):
        signKey =  Util.special_replace(ConsumerSecret)
        if not TokenSecret:
            TokenSecret = ""
        finalKey = signKey+"&"+TokenSecret
        print 'key:',finalKey,'==============------'
        return finalKey

    @staticmethod
    def special_replace(base_string):
        #&不编码
        urlcode_string = urllib.quote(base_string,"")

        urlcode_string = urlcode_string.replace("+","%20")
        urlcode_string = urlcode_string.replace("*","%2A")
        urlcode_string = urlcode_string.replace("%7E","~")

        return urlcode_string




class APIClient(object):
    """
    oauth1.0认证
    """
    def __init__(self,baseUrl,consumerKey,consumerSecret,access_token=None,access_secret=None,redirect_uri=None,oauth_version='1.0'):
        self.baseUrl = baseUrl
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.redirect_uri = redirect_uri
        self.oauth_version = oauth_version
        self.access_token = access_token
        self.access_secret = access_secret
        self.request_token = None
        self.request_secret = None
        self.oauth_callback = None
        self.oauth_verifier = None


    def set_oauth_verifier(self,oauth_verifier):
        self.oauth_verifier = oauth_verifier

    def set_request_token(self,request_token):
        self.request_token=request_token

    def get_request_token(self,oauth_callback='oob'):
        self.oauth_callback = oauth_callback
        value_dic = {}
        oauth_url = self.baseUrl + "/oauth/request_token"
        value_dic['oauth_callback']=oauth_callback
        value_dic['oauth_consumer_key']=self.consumerKey
        value_dic['oauth_signature_method']='HMAC-SHA1'
        value_dic['oauth_timestamp']=self.__get_timestamp()
        value_dic['oauth_nonce']= self.__get_nonce()
        value_dic['oauth_version'] = '1.0'
        oauth_signature = Util.sign_request(Util.getSignNameKey(self.consumerSecret),

                                                         Util.getBaseSignString('GET',oauth_url,1,
                                                                   oauth_callback=oauth_callback,
                                                                   oauth_consumer_key=self.consumerKey,
                                                                   oauth_signature_method='HMAC-SHA1',
                                                                   oauth_timestamp=self.__get_timestamp(),
                                                                   oauth_nonce = value_dic.get('oauth_nonce'),
                                                                   oauth_version = '1.0'
                                                                   )
                                                         )
        #print 'oauth_signature',oauth_signature
        value_dic['oauth_signature'] = oauth_signature
        page = Util.callHttp(self.baseUrl, "/oauth/request_token", 'GET', value_dic)
        print page
        request_dic = self.__result2dict(page)
        self.request_token = request_dic.get('oauth_token')
        self.request_secret = request_dic.get('oauth_token_secret')
        return "%s/oauth/authorize?oauth_token=%s" % (self.baseUrl,self.request_token),self.request_token,self.request_secret

    def get_access_token(self,request_token=None,oauth_verifier=None,request_secret=None):
        self.request_token = request_token
        self.oauth_verifier = oauth_verifier
        self.request_secret = request_secret
        if not oauth_verifier:
            raise ApiError('9', 'not have oauth_verifier')
        access_url = self.baseUrl+'/oauth/access_token'
        value_dic = self.__param2dic(oauth_consumer_key=self.consumerKey,oauth_token=self.request_token,
                                     oauth_verifier=self.oauth_verifier,oauth_signature_method='HMAC-SHA1',
                                     oauth_timestamp=self.__get_timestamp(),oauth_nonce=self.__get_nonce(),
                                     oauth_version='1.0')

        oauth_signature = Util.sign_request(Util.getSignNameKey(self.consumerSecret,self.request_secret),

                                                         Util.getBaseSignString('GET',access_url,1,
                                                                   oauth_consumer_key=self.consumerKey,
                                                                   oauth_token=self.request_token,
                                                                   oauth_verifier=self.oauth_verifier,
                                                                   oauth_signature_method='HMAC-SHA1',
                                                                   oauth_timestamp=self.__get_timestamp(),
                                                                   oauth_nonce = value_dic.get('oauth_nonce'),
                                                                   oauth_version = '1.0'
                                                                   )
                                                         )
        #print 'oauth_signature',oauth_signature
        value_dic['oauth_signature'] = oauth_signature
        print value_dic
        page = Util.callHttp(self.baseUrl, "/oauth/access_token", 'GET', value_dic)
        request_dic = self.__result2dict(page)
        self.access_token = request_dic.get('oauth_token')
        self.access_secret = request_dic.get('oauth_token_secret')
        return self.access_token,self.access_secret


    def get_user_info(self):
        """
        查看用户信息
        :param access_token:
        :param access_secret:
        :return:json
        """

        get_user_url = self.baseUrl + '/yws/open/user/get.json'
        header_string = self.__getSignHeader(get_user_url,'GET')
        page = ""
        try:
            page = Util.callHttp(self.baseUrl, "/yws/open/user/get.json", 'GET', header=header_string)
        except ApiError,e:
            print e
        return page


    def get_notebook_all(self):
        """
        查看用户全部笔记本
        :param access_token:
        :param access_secret:
        :return:json
        """
        notebook_all_url = self.baseUrl+'/yws/open/notebook/all.json'
        header_string = self.__getSignHeader(notebook_all_url,'POST')
        page = Util.callHttp(self.baseUrl, "/yws/open/notebook/all.json", 'POST', header=header_string)
        return page

    def get_notebook_list(self,notebook_path):
        """
        列出笔记本下的笔记
        :param notebook_path:
        :param access_token:
        :param access_sercret:
        :return:json
        """
        notebook_list_url = self.baseUrl+'/yws/open/notebook/list.json'
        header_dic = self.__param2dic(oauth_consumer_key=self.consumerKey,oauth_token=self.access_token,
                                        oauth_signature_method='HMAC-SHA1',oauth_timestamp=self.__get_timestamp(),
                                        oauth_nonce=self.__get_nonce(),oauth_version=self.oauth_version)

        oauth_signature = Util.sign_request(Util.getSignNameKey(self.consumerSecret,self.access_secret),
                                                         Util.getBaseSignString('POST',notebook_list_url,1,
                                                                   oauth_consumer_key=self.consumerKey,
                                                                   notebook = notebook_path,
                                                                   oauth_token=self.access_token,
                                                                   oauth_signature_method='HMAC-SHA1',
                                                                   oauth_timestamp=self.__get_timestamp(),
                                                                   oauth_nonce = header_dic.get('oauth_nonce'),
                                                                   oauth_version = self.oauth_version
                                                                   )
                                                         )
        header_dic['oauth_signature'] = oauth_signature
        header_string = self.__headerdict2String(header_dic)
        page = Util.callHttp(self.baseUrl, "/yws/open/notebook/list.json", 'POST', value_dic={'notebook':notebook_path}, header=header_string)
        return page

    def get_note(self, note_path):
        get_note_url = self.baseUrl+'/yws/open/note/get.json'
        header_dic = self.__param2dic(oauth_consumer_key=self.consumerKey,oauth_token=self.access_token,
                                        oauth_signature_method='HMAC-SHA1',oauth_timestamp=self.__get_timestamp(),
                                        oauth_nonce=self.__get_nonce(),oauth_version=self.oauth_version)

        oauth_signature = Util.sign_request(Util.getSignNameKey(self.consumerSecret,self.access_secret),
                                                         Util.getBaseSignString('POST',get_note_url,1,
                                                                   oauth_consumer_key=self.consumerKey,
                                                                   path = note_path,
                                                                   oauth_token=self.access_token,
                                                                   oauth_signature_method='HMAC-SHA1',
                                                                   oauth_timestamp=self.__get_timestamp(),
                                                                   oauth_nonce = header_dic.get('oauth_nonce'),
                                                                   oauth_version = self.oauth_version
                                                                   )
                                                         )
        header_dic['oauth_signature'] = oauth_signature
        header_string = self.__headerdict2String(header_dic)
        page = Util.callHttp(self.baseUrl, "/yws/open/note/get.json", 'POST', value_dic={'path': note_path}, header=header_string)
        return page

    def get_note_resource(self, resource_path):
        resource_path = self.baseUrl + "/yws/open/resource/download/8/5A80636AFCB046D1AEA794AA16C802EC"
        header_string = self.__getSignHeader(resource_path,'GET')
        page = Util.callHttp(self.baseUrl, resource_path, 'GET', header=header_string)
        return page

    def __get_timestamp(self):
        return int(time.time())

    def __get_nonce(self):
        #return str(random.randint(999999999999999,10000000000000000))
        return str(random.randint(9999,100000))

    def __result2dict(self,result):
        dic = {}
        for i in result.split('&'):
            dic.update({i.split('=')[0]:i.split('=')[1]})
        return dic

    def __param2dic(self,**kwargs):
        return kwargs

    def __headerdict2String(self, header_dic):
        header_list = []
        for header in header_dic:
             header_list.append(str(header)+'="'+str(header_dic.get(header))+'"')
        return ", ".join(header_list)

    def __getSignHeader(self,url,method):
        header_dic = self.__param2dic(oauth_consumer_key=self.consumerKey,oauth_token=self.access_token,
                                        oauth_signature_method='HMAC-SHA1',oauth_timestamp=self.__get_timestamp(),
                                        oauth_nonce=self.__get_nonce(),oauth_version=self.oauth_version)

        print header_dic,'-----------------'
        oauth_signature = Util.sign_request(Util.getSignNameKey(self.consumerSecret,self.access_secret),
                                                         Util.getBaseSignString(method,url,1,
                                                                   oauth_consumer_key=self.consumerKey,
                                                                   oauth_token=self.access_token,
                                                                   oauth_signature_method='HMAC-SHA1',
                                                                   oauth_timestamp=header_dic.get('oauth_timestamp'),
                                                                   oauth_nonce = header_dic.get('oauth_nonce'),
                                                                   oauth_version = self.oauth_version
                                                                   )
                                                         )
        #print 'oauth_signature',oauth_signature
        header_dic['oauth_signature'] = oauth_signature
        header_string = self.__headerdict2String(header_dic)
        return header_string



if __name__ == "__main__":
    print '----------start-----------'
    client = APIClient("http://note.youdao.com",'76c0ede9b5eaebab5e1d1dae506a54ab','f0d74cfe5ed0846430b69a1e2014bd1a',access_token="ff56fa310b5f4b23f34236d4ca63d6ce",access_secret="d553e2e77ee224e6f2f183eee45ff53d")
    #client.get_request_token()
    #url,requst_token,request_secret = client.get_request_token()
    #print url,requst_token,request_secret
    # client.set_oauth_verifier()

    #acc_token,acc_secret = client.get_access_token('194b8dfd2e8066f443f040643dab04b2','460889','d553e2e77ee224e6f2f183eee45ff53d')
    #print acc_token,acc_secret

    a = client.get_notebook_all()
    print a

    #a = client.get_notebook_list('V8ytS6J','d5ac9665d75eab5e31499fb1a8b0b424','4736dbaaa41d2e3ab5549d83fd29b970')
    #print a

    #a = client.get_note('web1372346282340','d5ac9665d75eab5e31499fb1a8b0b424','4736dbaaa41d2e3ab5549d83fd29b970')
    #print a

    #a = client.get_note_resource("",'d5ac9665d75eab5e31499fb1a8b0b424','4736dbaaa41d2e3ab5549d83fd29b970')
    #print a
    #print client.request_secret
    #print client.request_token
    #b = {'oauth_nonce': '8659250471185732', 'oauth_timestamp': 1372995358, 'oauth_signature_method': 'HMAC-SHA1', 'oauth_consumer_key': '76c0ede9b5eaebab5e1d1dae506a54ab', 'oauth_verifier': '360490', 'oauth_version': '1.0', 'oauth_token': 'f1c855280e2079802501ad148c0c8d41', 'oauth_signature': 'LCvr4EjLP6juJOVIOW6P096hq0Q=\n'}
    #print json.(b)








