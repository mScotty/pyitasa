#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) <2014> <Solkeera/mScotty>

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""


import os,pycurl, json, zipfile, sys
from BeautifulSoup import BeautifulSoup as beatsop
from StringIO import StringIO

class Itasa:

    ITASA={}
    ITASA["HTTPS"]=True
    ITASA["URL"]="//api.italiansubs.net/api/rest/"
    ITASA["APIKEY"]=""
    ITASA["JSON"]=True
    ITASA["AGENT"]="curl (Python-Curl; Linux-x11)"
    ITASA["AUTHCODE"]=""
    ITASA["COOKIES"]=[]
    ITASA["KEYS"]={'USER':"Itasa_Rest2_Server_Users",
                   'NEWS':"Itasa_Rest2_Server_News",
                   'SUBS':"Itasa_Rest2_Server_Subtitles"}
    ITASA["USER"]=""
    ITASA["PASS"]=""
    ITASA['LOGIN']=0
    ITASA['LAST_ACTION']=''
    
    SUBTITLE={}
    SUBTITLE['FILENAME']=''
    SUBTITLE['VERSION']=''
    SUBTITLE['NAME']=''

    ## serve per __headerFunction contiene tutti gli header che restituisce
    ## pycurl
    HEADERS={}
    
    # res curl
    FP=""
    
    def __init__(self):
        URL=self.ITASA["URL"]
        if self.ITASA["HTTPS"]==True: URL="https:"+URL
        else: URL="http:"+URL        
        self.ITASA["URL"]=URL


    def setHttps(self,boolean=True):
        self.ITASA['HTTPS']=boolean
    def setUrl(self,sUrl=''):
        self.ITASA['URL']=sUrl
    def setApiKey(self,sApikey=''):
        self.ITASA['APIKEY']=sApikey
    def setJson(self,boolean=True):
        self.ITASA['JSON']=boolean
    def setAgent(self,sAgent=''):
        self.ITASA['AGENT']=sAgent
    def setAuthCode(self,sAuthCode=''):
        self.ITASA['AUTHCODE']=sAuthCode
    def setUsername(self,sUsername=''):
        self.ITASA['USER']=sUsername
    def setPassword(self,sPassword=''):
        self.ITASA['PASS']=sPassword
    def setLogin(self,boolean=False):
        self.ITASA['LOGIN']=boolean
    def setLastAction(self,sAction):
        self.ITASA['LAST_ACTION']=''

    def setSubInfo(self,dInfo):
        sSubKey=self.ITASA['KEYS']['SUBS']
        dInfo=dInfo[sSubKey]['single']['subtitle']
        self.SUBTITLE['NAME']=dInfo['name']
        self.SUBTITLE['FILENAME']=dInfo['filename']
        self.SUBTITLE['VERSION']=dInfo['version']
        
    def getUsername(self):
        return self.ITASA['USER']
    def getPassword(self):
        return self.ITASA['PASS']
    def getAuthCode(self):
        return self.ITASA['AUTHCODE']
    def getLogin(self):
        return self.ITASA['LOGIN']
    def getLastAction(self):
        return self.ITASA['LAST_ACTION']
    def getUserAgent(self):
        return self.ITASA['AGENT']
    
    def isLogged(self):
        bLogin=self.getLogin()
	if bLogin==True:
            return True
        return False

    def __headerFunction(self,header_line):
        header_line=header_line.decode('iso-8859-1')
        if ':' not in header_line:
            return
        name, value=header_line.split(':',1)
        name=name.strip()
        value=value.strip()
        name=name.lower()        
        self.HEADERS[self.__convertMe(name)]=self.__convertMe(value)

    ## curl write
    def __write(self,sData,headers=''):
        self.FP=pycurl.Curl()
        self.FP.setopt(self.FP.USERAGENT,self.getUserAgent())
        
        if sData=='':
            return False
        if "?" not in sData: sData=sData+"?"
        else: sData=sData+"&"
        sData+="apikey={sApikey}".format(sApikey=self.ITASA["APIKEY"])
        
        if self.ITASA["JSON"]==True:
            sData+="&format=json"
            
        sData=self.ITASA["URL"]+sData

        #self.ITASA['URL']
        
        self.FP.setopt(self.FP.URL,sData)
        if len(self.ITASA['COOKIES'])>0:
            self.FP.setopt(pycurl.COOKIELIST, 'ALL')
            self.FP.setopt(self.FP.COOKIE,'; '.join(x for x in self.ITASA['COOKIES']))
        
        return self.__read()

    ## curl read
    def __read(self):
        oData = StringIO()
        
        self.FP.setopt(self.FP.HEADERFUNCTION, self.__headerFunction)
        self.FP.setopt(self.FP.SSL_VERIFYPEER, False)
        self.FP.setopt(self.FP.WRITEFUNCTION,oData.write)
        self.FP.setopt(self.FP.FOLLOWLOCATION,True)
        self.FP.perform()
        rVal=oData

        if self.ITASA['LAST_ACTION']=='DOWNLOAD': self.ITASA['LAST_ACTION']=''
            
        self.__close()        
        return rVal

    ## chiude handler curl
    def __close(self):
        self.FP.close()

    
    def loginSite(self):
        ## tramite le api non e' possibile scaricare i sub
        ## per faciliatre il lavoro ci affidiamo a urllib2 e urllib
        ## nota: html_parser importa bs
        ## !!! effettuare sempre il login tramite Itasa.login, e poi effettuare
        ##	il login con Itasa.loginSite
        
        import urllib2
        import urllib

        headers={}
        headers['User-Agent']=self.ITASA['AGENT']
        headers['Cookie']='; '.join(x for x in self.ITASA['COOKIES'])

        url='http://www.italiansubs.net/'

        req=urllib2.Request(url,headers=headers)
        html_data=urllib2.urlopen(req)

        ## dict form con i dati
        dForm=self.__htmlParser(html_data.read().decode("utf-8"))

        ## utilizzo dopo il cookie
        self.ITASA['COOKIES'].append(html_data.info()['Set-Cookie'].split(';')[0])

        headers['Cookie']='; '.join(x for x in self.ITASA['COOKIES'])

        dForm['username']=self.getUsername()
        dForm['passwd']=self.getPassword()

        ## login sito utilizzando i vecchi cookie

        sData=urllib.urlencode(dForm)
        request=urllib2.Request(url,sData,headers)
        response=urllib2.urlopen(request)
        
        if not response.info().has_key('Set-Cookie'):
            return True
        return False
    
    def getNews(self,bSearch=False,nId=0,sQ='',nPage=0):
        """
        Ritorna Stringa o Boolean
        
        """
        bRet=False
        sWrite=''
        if bSearch==True and len(sQ)>0:
            sWrite="news/search?q={sQuery}&page={nPage}".format(sQuery=sQ,nPage=nPage)
        if not bSearch:
            if nId==0:
                sWrite="news"
            else:
                sWrite="news/{nId}".format(nId=nId)
        bRet=self.__write(sWrite)
        return bRet

    def getShow(self,sAction='',dParams={}):
        """
	
        | Azione               | URL                         | PARAMS                   |
        |----------------------+-----------------------------+--------------------------|
        | Lista degli show     | shows?...                   | nessuno                  |
        |----------------------+-----------------------------+--------------------------|
        | Dettagli show        | shows/{nId}?...             | nId -> Id dello show     |
        |----------------------+-----------------------------+--------------------------|
        | Prossimi Episodi     | shows/nextepisodes?...      | nessuno                  |
        |----------------------+-----------------------------+--------------------------|
        | Immagine folder show | shows/{nId}/folderThumb?... | nId -> Id dello show     |
        |----------------------+-----------------------------+--------------------------|
        | Ricerca Show         | shows?search...             | q -> stringa da cercare  |
        |                      |                             | page -> numero di pagina |
        |                      |                             | opzionale                |
        |----------------------+-----------------------------+--------------------------|

        
        """
        lActions=['get','info','next_episode','image','search']
        
        if sAction not in lActions:
            return False

        nId=0
        if dParams.has_key("ID"):
            nId=dParams["ID"]

        if not dParams.has_key('PAGE'):
            dParams['PAGE']=0
            
        sWrite='shows'
        if sAction=='info':
            if nId > 0: sWrite+='/{nId}'.format(nId=nId)
        elif sAction=='next_episode':
            sWrite+='/nextepisodes'
        elif sAction=='image':
            if nId > 0: sWrite+='/{nId}/folderThumb'.format(nId=nId)
        elif sAction=='search':
            sWrite+='/search?q={sQuery}&page={nPage}'.format(sQuery=dParams['QUERY'],nPage=dParams['PAGE'])
            
        bRet=self.__write(sWrite)
        
        return bRet

    def getSubtitles(self,sAction='',dParams={}):

        """
        sAction		stringa 	azione da eseguire
        dParams 	dizionario 	parametri da passare

        cosa fa: 	cerca i sottotitoli/dettagli seguendo la tabella sotto

        
        | Azione           | URL                  | Params                                   |
        |------------------+----------------------+------------------------------------------|
        | Subs di uno show | subtitles?...        | show_id -> numerico id dello show        |
        |                  |                      | version -> string web-dl,720p, opzionale |
        |                  |                      | page -> numerico pagina                  |
        |------------------+----------------------+------------------------------------------|
        | Dettagli sub     | subtitles/{nId}?...  | nId -> numerico id dello show            |
        |------------------+----------------------+------------------------------------------|
        | Ricerca sub      | subtitles/search?... | q -> stringa lo show da cercare          |
        |                  |                      | show_id -> numerico id dello show        |
        |                  |                      | version -> string web-dl,720p, opzionale |
        |                  |                      | page -> numerico pagina                  |
        |------------------+----------------------+------------------------------------------|


        ritorna boolean o dati dizionario (leggere documentazione itasa)
        
        """
        bRet=False
        lActions=['get','info','search','download']
        lVersions=["1080i","1080p","720p","bdrip","bluray","dvdrip","hdtv","hr","web-dl"]
        
        if sAction not in lActions: return False
        if dParams.has_key('VERSION'):
            if dParams['VERSION'].lower() not in lVersions:
                dParams['VERSION']="web-dl"
        else:
            dParams['VERSION']="web-dl"
        
        nShowId=0
        if dParams.has_key("ID"):
            nShowId=dParams['ID']

        sWrite='subtitles'

        if sAction=='get':
            sWrite+='?show_id={nShowId}'.format(nShowId=nShowId)
            if dParams.has_key('VERSION'):
                sWrite+="&version={sVersion}".format(sVersion=dParams['VERSION'])
            if dParams.has_key('PAGE'):
                sWrite+="&page={nPage}".format(nPage=dParams['PAGE'])
                
        if sAction=='info':
            sWrite+='/{nId}'.format(nId=nShowId)
            
        if sAction=='search':
            sWrite+="/search?q={sQuery}&show_id={nShowId}".format(sQuery=dParams['QUERY'],nShowId=nShowId)
            if dParams.has_key('VERSION'):
                sWrite+='&version={sVersion}'.format(sVersion=dParams['VERSION'])
            if dParams.has_key('PAGE'):
                sWrite+='&page={nPage}'.format(nPage=dParams['PAGE'])
                
        if sAction=='download':
            sWrite+=self.__download(nShowId)
        bRet=self.__write(sWrite)
        
        return bRet



    def login(self,sUser='',sPass=''):
        """
        sUser 	stringa 	username dell'utente
        sPass	stringa 	password dell'utente
        
        cosa fa: esegue il login su itasa, memorizza il codice di autenticazione in memoria
        ritorna: boolean
        """
        if len(sUser)==0:
            sUser=self.getUsername().strip()
        if len(sPass)==0:
            sPass=self.getPassword().strip()

        self.setUsername(sUser)
        self.setPassword(sPass)
        sWrite='users/login?username={username}&password={password}'.format(username=sUser,password=sPass)
        
        # falso o oggeto StringIO
        rVal=self.__write(sWrite)
        self.ITASA["COOKIES"].append(self.HEADERS['set-cookie'].strip().split(';')[0])
        if rVal:
            dBuffer=json.loads(rVal.getvalue())
            if dBuffer.has_key(self.ITASA['KEYS']['USER']):
                self.setAuthCode(dBuffer[self.ITASA["KEYS"]['USER']]['login']['user']['authcode'])
                self.setLogin(True)
            else:
                self.setLogin(False)
        return self.isLogged()

    ## download dei sottotioli
    ## la funzione esegue il login se non effettuato
    def __download(self,nIdSub):
        if not self.isLogged():
            bLogged=self.login()        

        dInfo=self.getSubtitles('info',{'ID':nIdSub})
        dInfo=json.loads(dInfo.getvalue())
        dInfo=self.__convertMe(dInfo)
        self.setSubInfo(dInfo)

        if self.isLogged():
            if nIdSub > 0:
                sWrite='/download?authcode={sAuthCode}&subtitle_id={nId}'.format(nId=nIdSub,sAuthCode=self.getAuthCode())
                self.ITASA['LAST_ACTION']='DOWNLOAD'
                return sWrite            
        return False

    def __convertMe(self,data):
        if isinstance(data,dict):
            dictionary={}
            for key,val in data.iteritems():
                dictionary[self.__convertMe(key)]=self.__convertMe(val)
            return dictionary
        if isinstance(data,list):
            return [convertMe(elem) for elem in data]
        if isinstance(data,unicode):
            return data.encode('utf-8')
        else:
            return data

        
    def search(self,dSerie):
        """
        Cerca uno show
        ritorna id Show
        """
        if len(dSerie)<1:
            return False
        dSearch={}
        dNews=self.__convertMe(json.loads(self.getNews(bSearch=True,nId=0,sQ=dSerie['NOME'],nPage=0).getvalue()))
        bKey=False
        if dNews.has_key(self.ITASA['KEYS']['NEWS']):
            dNews=dNews[self.ITASA['KEYS']['NEWS']]
            if dNews.has_key('search'):
                dNews=dNews['search']
                if dNews.has_key('news'):
                    dNews=dNews['news']
                    bKey=True
        if bKey:
            dSearch=dNews
        dNews=None

        dSerie['ID']=self.__getValueFromNewsSearch('show_id',dSearch)
        dSerie['CERCATO']=dSerie['NOME']
        dSerie['NOME']=self.__getValueFromNewsSearch('show_name',dSearch)
        dSerie['FOUND']=True
        
        return dSerie

    def getSubFromName(self,dSerie):
        """
        """
        
        sNome=dSerie['NOME']+' '+dSerie['STAGIONE']+'x'+dSerie['EPISODIO']
        dSerie['VQUALITA']=dSerie['QUALITA']
        dSub=self.__getSubFromBuffer(self.__convertMe(json.loads(self.getSubtitles('get',{"ID":dSerie['ID'],"PAGE":0}).getvalue())))

        if dSub:
            nPage=0
            bFound=False
            nPages=int(dSub['pages'])
            bEnd=False
            while not bFound and not bEnd:
                for key in dSub['subtitles']:
                    if dSub['subtitles'][key]['name']==sNome:
                        dSerie['QUALITA']=dSub['subtitles'][key]['version']
                        dSerie['SUBID']=dSub['subtitles'][key]['id']
                        dSerie['SUBFOUND']=True
                        bFound=True
                if not bFound:
                    nPage=int(dSub['page'])+1
                    if nPage <= nPages:
                        dSub=self.__getSubFromBuffer(self.__convertMe(json.loads(self.getSubtitles('get',{"ID":dSerie['ID'],"PAGE":nPage}).getvalue())))
                    else:
                        bEnd=True
                
        return dSerie
                
    def __getSubFromBuffer(self,dSub):

        bSubs=False
        if dSub.has_key(self.ITASA['KEYS']['SUBS']):
            dSub=dSub[self.ITASA['KEYS']['SUBS']]
            if dSub.has_key('direct'):
                dSub=dSub['direct']
            else:
                return False
        return dSub
    def __getValueFromNewsSearch(self,sValue,dSearch):
        """
        Prende il primo show_id dalla ricerca
        """
        rVal=''
        if isinstance(dSearch,dict):
            if dSearch.has_key('key_0'):
                rVal=dSearch['key_0'][sValue]
        return rVal
    
    #def __getShowInfo(self,dSearch):
    #   print json.loads(self.getShow('info',dSearch))
        
    #def extractCookie(self):
    #return self.HEADERS['set-cookie'].strip().split(';')[0]

    ## parsing degli elementi minimi per effettuare un login
    def __htmlParser(self,html_data):

        html_proc = beatsop(html_data)
    	#form
        txtinput = html_proc.findAll('form', {'name':'login'})

    	## cerca tra gli elementi di tipo hidden/submit nel form loginè
        listform = ["submit","hidden"]
        rVal={}
        for elem in txtinput[0].findAll('input',{'type':listform}):
            rVal[self.__convertMe(elem['name'])]=self.__convertMe(elem['value'])        
        return rVal
    
    def getFile(self,dSerie,data):

        sPath=''
        sZipPath='./'+dSerie['ORIGINAL']
        sSubPath='./'+dSerie['ORIGINAL']+'.srt'
        try:
            fp=open(sZipPath,'wb')
            fp.write(data)
            fp.close()
        except Exception, ex:
            print 'Cannot Create File'

        try:
            if os.path.isfile(sZipPath):
                
                zf=zipfile.ZipFile(sZipPath,'r')
                binData=zf.read(zf.namelist()[0])
                os.remove(sZipPath)
                
                fp=open(sSubPath,'wb')
                
                if binData:                        
                    fp.write(binData)
                else:
                    fp.write('FILE SUBS NOT FOUND')
                fp.close()
                
                binData=None                
                
                sPath=os.path.realpath(sSubPath)
                    
        except Exception, ex:
            print 'Cannot find subs'
            
        return sPath

def GetName(sFileName=''):
    import re
    
    rVal=False
    sName=sFileName
    
    p=re.match(r"(?P<NOME>([a-zA-Z\.])+)(?P<STAGIONE>[Ss][0-9]{1,2})(?P<EPISODIO>[Ee][0-9]{1,2})\.(?P<QUALITA>720|1080)[p]",sName)
    if p:
        dApp={}
        dApp['NOME']=re.sub(r"\.",' ',p.group('NOME'))[:-1]
        dApp['STAGIONE']=p.group('STAGIONE')[2:3]
        dApp['EPISODIO']=p.group('EPISODIO')[1:3]
        dApp['QUALITA']=p.group('QUALITA')
        dApp['SUBFOUND']=False
        dApp['FOUND']=False
        dApp['ORIGINAL']='.'.join(x for x in sFileName.split('.')[:-1])
        rVal=dApp 
    return rVal

if __name__=='__main__':
    
    ## USERNAME italiansubs.net
    USERNAME='MyUser'
    ## PASSWORD italiansubs.net
    PASSWORD='MyPass'



    if len(sys.argv)>1:
        try:
            sName=u""+sys.argv[1]
            dName=GetName(sName)
            if not dName:
                exit('Error Name')
        except Exception:
            exit('Errore nome')
    else:
        exit('Errore nessun nome trovato')

    oItasa=Itasa()
    ## ritorna id show
    dSearch=oItasa.search(dName)
    dSub=oItasa.getSubFromName(dSearch)

    data=''
    if dSub['SUBFOUND']==True:
        oItasa.login(USERNAME,PASSWORD)
        oItasa.loginSite()
        data=oItasa.getSubtitles('download',{'ID':dSub['SUBID']}).getvalue()
        sPath=''
        if data:
            sPath=oItasa.getFile(dSearch,data)
        print sPath
    else:
        print False
    oItasa=None
