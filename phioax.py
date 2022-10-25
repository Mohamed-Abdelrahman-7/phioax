import  argparse,quopri,re,hashlib,email,os,urllib,urllib.parse,vt,json,base64,dkim
from datetime import datetime
from email import parser
import dns.resolver
from textwrap import wrap
#function to load the eml from the path specified by the user 
def eml_grabber(pth):
    """reads the eml file from the path specified and returns the filename and binary content of the file"""
    try:
        with open(pth,'rb') as f:
            emlBytesObject=f.read()
            print("\nThe eml file is read successully, cleanining and parsing process is being initiated....")
            fileName=os.path.split(f.name)[-1]
            emailParser=parser.BytesParser()
            EmailMessageObject=emailParser.parsebytes(emlBytesObject)
            return emlBytesObject,fileName,EmailMessageObject
    except FileNotFoundError:
        print("the file you specified doesn't exist !!!")
        exit(1)
    except Exception as e:
        print("an error {} occured while reading the file !!!".format(e))
        exit(1)
# defining a fucntion to decode  quoted printable characters and return a clean version of the eml file
def quo_cleaner(messageObject):
    """decodes base64 and quoted printable encoded email parts 
    takes email.message object and returns a string of the message after cleaning """
    for part in messageObject.walk():
        if "text" in part.get_content_type() and part.get("Content-Transfer-Encoding") == "base64":
            part.set_payload(base64.b64decode(part.get_payload().encode()).decode())
        elif "text" in part.get_content_type() and part.get("Content-Transfer-Encoding") == "quoted-printable":
            part.set_payload(quopri.decodestring(part.get_payload()).decode())
    return messageObject.as_string() 
#function to extract public IPs and urls
def extract_ioa(emlClean):
    """extracts public IPs and URLs found in the email content"""
    ipsLs=re.findall(r'(?:\d{1,3}\.){3}\d{1,3}',emlClean)
    pubIps=[]
    for i in ipsLs:
        if  i.startswith(("192.168.","10.","255.255.255.255")):
            continue
        elif  i.startswith("172") and 16<=int(i.split('.')[1])<32:
                continue
        elif any(int(x)>255 for x in i.split('.')):
            continue 
        else:
            pubIps.append(i)
    urls=[urllib.parse.unquote(x) for x in re.findall(r'https?(?:://|%3A%2F%2F)[^\s\"><]+',emlClean)]
    urlsFromSafeLinks= [urllib.parse.unquote(x) for x in  re.findall(r'safelinks.+?outlook\.com.+?(https?(?:://|%3A%2F%2F)[^\s\"><]+)','\n'.join(urls))]
    urlsFromFireeyeProtect=[urllib.parse.unquote(x) for x in re.findall(r'protect.+?fireeye\.com.+?(https?(?:://|%3A%2F%2F)[^\s\"><]+)','\n'.join(urls))]
    urlsFromMimecastProtect=[urllib.parse.unquote(x) for x in re.findall(r'protect.+?mimecast\.com.+?(https?(?:://|%3A%2F%2F)[^\s\"><]+)','\n'.join(urls))]
    return set(pubIps),set(urls),set(urlsFromSafeLinks),set(urlsFromFireeyeProtect),set(urlsFromMimecastProtect)
#function to get a list of attachements and their corresponding file hashes [Optionally dump the attachments to your local storage]
def hash_ex(eml,dumpPath):
    """get a list of attachements and their corresponding file hashes [Optionally dump the attachments to your local storage] if argument d (-d) is set by the user while excuting the script"""
    nameHash={}
    msgObj=email.message_from_bytes(eml)
    for part in msgObj.walk():
        if part.get_content_disposition()=='multipart':
            continue
        fileName=part.get_filename()
        if fileName!=None:
            nameHash[fileName]=hashlib.sha256(part.get_payload(decode=True)).hexdigest()
            if dumpPath != None:
                try:
                    with open(os.path.join(dumpPath,fileName),'wb') as f:
                     f.write(part.get_payload(decode=True))
                except Exception as e:
                     print("an error {} occured while dumping{} and the attachments won't be dumped!!! please check your write permission on the specified directory".format(e,fileName))
    return nameHash
# function to extract datetimes to detect any datetime anomlaies
def datetimex(eml):
   """extracts all times found in the email and converts them to readable ISO formatted times, so the analyst can find any time anomalies
   returns: iso timestamps [list] and the time delta between earler and older timestamps obverved "string" """
   rDatetime= re.findall(r'(?<=Received)[^;]*;[^\d]+(.+\d)',eml)
   dDatetime=re.findall(r'(?<=Date)[^,]*,[^\d]+(.+\d)',eml)
   isoDatetimes=[]
   for i in rDatetime:
     try:
        isoDatetimes.append(datetime.strptime(i,"%d %b %Y %H:%M:%S %z").isoformat())
     except:
        continue
   for j in dDatetime:
    try:
            isoDatetimes.append(datetime.strptime(j,"%d %b %Y %H:%M:%S %z").isoformat())
    except:
            continue
   isoDatetimes=sorted(isoDatetimes,key=datetime.fromisoformat)
   timeDiff="time deviation of observed timestamps is {} days and {} seconds\n".format((datetime.fromisoformat(isoDatetimes[-1])-datetime.fromisoformat(isoDatetimes[0])).days,\
    (datetime.fromisoformat(isoDatetimes[-1])-datetime.fromisoformat(isoDatetimes[0])).seconds) 
   return isoDatetimes,timeDiff
def ip_intel_vt(client,ip):
    """ a function that will take vt.Client object and ip (string) as a parmaters and perform IP reputation, reolution, SSL info analysis for this IP"""
    try:
        ipReport=client.get_object("/ip_addresses/{}".format(ip))
        reputation="VT analysis: Ip is located in ({}) and belongs to ({}). stats: It's reported as malicious by {}, suspicious by {}, harmless by {} and undected by {}\n"\
                .format(ipReport.get("country"),ipReport.get("as_owner"),*[ipReport.get('last_analysis_stats')[key] for key in ['malicious','suspicious','harmless','undetected']])
    except:
        reputation="No reputation data is available for that IP \n"
    try:
        ipSslCert=list(client.iterator("/ip_addresses/{}/historical_ssl_certificates".format(ip),limit=1))[0]
        sslInfo="VT SSL cert analysis: this ip has an SSL ceritiface issued by ({}) to a subject name ({}) not_after ({}) and not before ({}). first seen at ({}) and it listens to the ssl service on port ({})\n".format(ipSslCert.issuer['O'],\
    ipSslCert.subject['CN'],ipSslCert.validity['not_after'],ipSslCert.validity['not_before'],*[ipSslCert.context_attributes[key] for key in ['first_seen_date','port']])
    except:
        sslInfo="There is no SSL certificate available for that IP\n"
    
    hosts="This IP found serving the following hosts:\n"
    try:
        ipRes=client.iterator("/ip_addresses/{}/resolutions".format(ip))
        for host in ipRes:
         hosts+=host.host_name +" at "+ datetime.isoformat(host.date)+'\n'
    except:
        pass
    return reputation,sslInfo,hosts
def hash_intel_vt(client,hash):
    """take a vt.Client object and a filehash "string" and returns the last_analysis_stats for that hash"""
    parameters={'query':hash}
    filehashReport=""
    try:
        hashReport=client.iterator("/search",params=parameters)
        for i in hashReport:
            stats=i.get("last_analysis_stats")
            filehashReport+="VirusTotal filehash analysis: filehash is reported as harmless by ({}), type unsupported by ({}), suspicious by ({}),  malicious by ({}) and undected by ({})\n"\
                .format(*[stats.get(key) for key in ["harmless","type-unsupported","suspicious","malicious","undetected"]])
        if len(filehashReport)==0:
            filehashReport="VirusTotal doesn't have information available for that filehash !!\n"
    except Exception as e:
        filehashReport="an error {} occured while trying to query VT for the filehash !!".format(e)
    return filehashReport   
def domain_intel_vt(client,hostname):
    try:
        domainObject=client.get_object("/domains/{}".format(hostname))
        domainReport="VT analysis: last dns records found for the domain are: \n {} \nstats: It's reported as harmless by {}, malicious by {}, suspicious by {} and undected by {}\n\
the domain is registered by {} at {}\nlast https certificate for that domain issued by {} with a subject {} not after {} and not before {}"\
                .format('\n'.join(["  -{} record with value {} and ttl {}".format(*[record[key] for key in ['type','value','ttl']]) for record in domainObject.get("last_dns_records")])\
                    ,*[domainObject.get('last_analysis_stats')[key] for key in ['harmless','malicious','suspicious','undetected']],domainObject.get('registrar'),\
                        datetime.isoformat(datetime.fromtimestamp(domainObject.get("creation_date"))) if domainObject.get("creation_date") !=None else "Unknown" \
                            ,domainObject.get("last_https_certificate")["issuer"]["O"],\
                            domainObject.get("last_https_certificate")["subject"]["CN"],*[domainObject.get("last_https_certificate")["validity"][key] for key in ["not_after","not_before"]])    
    except Exception as e:
     domainReport="An error {} occured while trying to get domain information from VirusTotal\n".format(e)
    return domainReport
def spf_fetcher(domain:str) -> tuple:
    """takes the sender's domain and makes a query for the TXT record for that domain to get the IPs of authorized MTAs for the domain by ietrating through the SPF record 
    it also returns the SPF fail policy whther hard or soft fail"""
    def digger(domain):
        spfEntriess=[]
        authorizedMx=[]
        txtRecord=dns.resolver.resolve(domain , 'TXT')
        for entry in txtRecord:
            if "spf" in str(entry):
                spfEntriess.append(str(entry))
        if len(spfEntriess) > 0:
            for spfEntry in spfEntriess:
                includes=re.findall(r'(?<=include:)[^\s]+',spfEntry)
                if len(includes)>0:
                    mxIps=re.findall(r'(?:(?<=ip4:)|(?<=ip6:))[^\s]+',spfEntry) 
                    authorizedMx= mxIps + [digger(include) for include in includes]
                else:
                    authorizedMx=re.findall(r'(?:(?<=ip4:)|(?<=ip6:))[^\s]+',spfEntry)
            return authorizedMx
        else:
            return None
    def check_fail_action(domain):
        failActions=[]
        txtRecord=dns.resolver.resolve(domain , 'TXT')
        for entry in txtRecord:
            if "spf" in str(entry):
                failActions+=re.findall(r'.all',str(entry))
        return failActions
    return digger(domain),check_fail_action(domain)
def main():
    argP=argparse.ArgumentParser(description="This tool is developed to help SOC analysts extracting Indicator of Attack from a suspicious email to check them agianst  OSINT resources")
    argP.add_argument("-p","--path",required=True,type=str,help=">>> Mandatory: the path of the eml file")
    argP.add_argument("-d","--dump",nargs='?',const='.',help=">>> Optional: dumps the attachments to the path you specify [or to the current directory if not specified] for more manual analysis")
    args=argP.parse_args()
    emlBinary,fileName,messageObject=eml_grabber(args.path)
    emlClean=quo_cleaner(messageObject)
    ips,urls,urlsFromSafeLink,urlsFromFireeyeProtect,urlsFromMimecastProtect=extract_ioa(emlClean)
    nameHash=hash_ex(emlBinary,args.dump)
    isoDatetimes,timeDiff=datetimex(emlClean)
    hostNames=set(map(lambda x: urllib.parse.urlparse(x).hostname,(urls.union(urlsFromSafeLink)).union(urlsFromFireeyeProtect)))
    with open('api_keys.json','rt') as jsf:
        try:
            vtClient=vt.Client(json.load(jsf)["VT_api_key"])
        except:
            vtClient=None
    try:
        with open(fileName+'_anlysis.txt','wt') as o:
            o.write("*********************Message Authenticity Analysis ***********************************\n\n")
            fromSender=messageObject.get_all("From")[0] if messageObject.get_all("From") !=None else ''
            fromDomain=re.search(r'(?<=@)[^>]+',fromSender)[0]
            o.write("- The email is sent from: {}\n".format(fromSender))
            o.write("- Return Path is: {}\n".format(messageObject.get_all("Return-Path"))) if messageObject.get_all("Return-Path") !=None else o.write("- Return Path header doesn't exist\n")
            receivedHeaders=[x.replace('\n','') for x in messageObject.get_all("Received")]
            if len(receivedHeaders) > 1:
                sortedcReceivedHeaders=sorted([x.replace('\r','') for x in receivedHeaders],key=lambda x:datetime.strptime(re.findall(r'[^;]*;[^\d]+(.+\d)',x)[0],"%d %b %Y %H:%M:%S %z").isoformat())
            else:
                sortedcReceivedHeaders=receivedHeaders
            firsthops=[]
            for i in sortedcReceivedHeaders:
                firsthops.append(i)
                if any(j in i for j in ips):
                    break
            o.write("- The first hop/s in the email flow (MTA the message started from) \n   ++++{}\n".format("\n   ++++".join(firsthops)))
            authResult=messageObject.get("Authentication-Results")
            o.write("- Authentication Results header exists with the following results: \n  {}\n".format(authResult)) if authResult !=None else o.write("- Authentication Results header doesn't exist !\n")
            o.write("- Manual DKIM Verification pass\n") if dkim.verify(emlBinary) else o.write("- Manual DKIM verification failed\n")
            cv, results, comment = dkim.arc_verify(emlBinary) 
            o.write("- Manual ARC verification: cv=%s %s\n" % (cv, comment))
            if spf_fetcher(fromDomain)[0] != None:
                o.write("- Getting Authorized MXs and fail action from SPF entry in  Domain DNS TXT record\n\
    MX:\n{}\n".format('\n'.join(wrap(str(spf_fetcher(fromDomain)[0]),width=175,initial_indent='       ',subsequent_indent='       '))))
                o.write("\n       SPF violation policy for the domain {} is hard fail\n\n".format(fromDomain)) if '~all' not in spf_fetcher(fromDomain)[1] else o.write("\n     SPF violation policy for the domain {} is soft fail\n\n".format(fromDomain))
            else:
                o.write("- Couldn't get  Authorized MXs from SPF entry in  Domain DNS TXT record\n") 
            o.write("- mail client IP address: {}\n".format(messageObject.get_all("X-Originating-IP")))         
            o.write("- Interesting Microsoft headers:\n\
    {}\n    {}\n    {}\n\n".format(*[x+': '+messageObject.get_all(x)[0] if messageObject.get_all(x) !=None else x+": doesn' exist" for x in ["x-ms-exchange-organization-originalclientipaddress","x-ms-exchange-organization-originalserveripaddress","X-MS-Has-Attach"]]))
            o.write("*********************list of IPs extracted***********************************\n\n")
            if vtClient !=None:
                for ip in ips:
                    o.write('>>>'+ip+'\n\n')
                    reputation,sslInfo,hosts=ip_intel_vt(vtClient,ip)
                    o.write(reputation+'\n'+sslInfo+'\n'+hosts+'\n')
            else:
                [o.write('>>>'+ip+'\n') for ip in ips] 
            o.write('\n*******************list of URLs extracted***********************************\n\n')
            [o.write(url+'\n') for url in urls]
            o.write('\n**************list of URLs extracted from outlook safe links****************\n\n')
            [o.write(url+'\n') for url in urlsFromSafeLink]
            o.write('\n**************list of URLs extracted from fireeye protect links****************\n\n')
            [o.write(url+'\n') for url in urlsFromFireeyeProtect]
            o.write('\n**************list of URLs extracted from mimecast protect links****************\n\n')
            [o.write(url+'\n') for url in urlsFromMimecastProtect]
            o.write('\n*****************list of hostnems extracted*********************************\n\n')
            if vtClient !=None:
                for hostname in hostNames:
                    o.write('>>>'+hostname+'\n')
                    domainReport=domain_intel_vt(vtClient,hostname)
                    o.write(domainReport+'\n\n')
            else:
                [o.write(hostname+'\n') for hostname in hostNames] 
            o.write('\n*************list of attachmnets and their filehashes extracted*************\n\n')
            if vtClient !=None:
                for key in nameHash.keys():
                    o.write(key+": {}\n".format(nameHash[key])+'\n')
                    filehashReport=hash_intel_vt(vtClient,nameHash[key])
                    o.write(filehashReport+'\n\n')
            else:
                [o.write(key+": {}\n".format(nameHash[key])) for key in nameHash.keys()]
            o.write('\n*****************list of timestamps extracted*******************************\n\n')
            [o.write(isodatetime+'\n') for isodatetime in isoDatetimes]
            o.write('\n'+timeDiff)
            o.write('\n****************************************************************************\n\
****************************************************************************\n')
            o.write("\n\nThanks for your support by using the tool! for any comments and issues please drop me a message on https://www.linkedin.com/in/moabdelrahman/ \n\n ")
    except Exception as e:
        print("an error {} occured while trying to create the analysis file! please check your permissions".format(e))
        exit(1)
    print("\nGreat!!! the IoAs extracted successfully please check {}_analysis.txt\n".format(fileName))
if __name__=='__main__':
    main()