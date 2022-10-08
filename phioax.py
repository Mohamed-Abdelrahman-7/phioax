import  argparse,quopri,re,hashlib,email,os,urllib,urllib.parse,vt,json
from pydoc import cli
from datetime import datetime

#function to load the eml from the path specified by the user 
def eml_grabber(pth):
    """reads the eml file from the path specified and returns the filename and binary content of the file"""
    try:
        with open(pth,'rb') as f:
            eml=f.read()
            print("\nThe eml file is read successully, cleanining and parsing process is being initiated....")
            fileName=os.path.split(f.name)[-1]
            return eml,fileName
    except FileNotFoundError:
        print("the file you specified doesn't exist !!!")
        exit(1)
    except Exception as e:
        print("an error {} occured while reading the file !!!".format(e))
        exit(1)
    

# defining a fucntion to decode  quoted printable characters and return a clean version of the eml file
def quo_cleaner(eml):
    """decode quoted printable characters """
    try:
        emlClean=quopri.decodestring(eml)
        return emlClean.decode(errors='ignore')
    except Exception as e:
        print("an error {} occured while cleaning quoted printable characters the program will process the eml file as is without cleaning !!!".format(e))
        return(eml.decode(errors='ignore'))
    

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
    urls=[urllib.parse.unquote(x) for x in re.findall(r'https?://[^\s\"><]+',emlClean)]
    urlsFromSafeLinks=re.findall(r'safelinks.+?outlook\.com.+?(https?://[^\s\"><]+)','\n'.join(urls))
    return set(pubIps),set(urls),set(urlsFromSafeLinks)

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
   """extracts all times found in the email and converts them to readable ISO formatted times so the analyst can find any time anomalies"""
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
   return isoDatetimes

def ip_intel_vt(client,ip):
    ipReport=client.get_object("/ip_addresses/{}".format(ip))
    """ a function that will take vt.Client object and ip (string) as a parmaters and perform IP reputation, reolution, SSL info analysis for this IP"""
    reputation="VT analysis: Ip is located in ({}) and belongs to ({}). stats: It's reported as malicious by {}, suspicious by {}, harmless by {} and undected by {}\n"\
                .format(ipReport.get("country"),ipReport.get("as_owner"),*[ipReport.get('last_analysis_stats')[key] for key in ['malicious','suspicious','harmless','undetected']])
    try:
        ipSslCert=list(client.iterator("/ip_addresses/{}/historical_ssl_certificates".format(ip),limit=1))[0]
        sslInfo="VT SSL cert analysis: this ip has an SSL ceritiface issued by ({}) to a subject name ({}) not_after ({}) and not before ({}). first seen at ({}) and it listens to the ssl service on port ({})\n".format(ipSslCert.issuer['O'],\
    ipSslCert.subject['CN'],ipSslCert.validity['not_after'],ipSslCert.validity['not_before'],*[ipSslCert.context_attributes[key] for key in ['first_seen_date','port']])
    except:
        sslInfo="There is no SSL certificate available for that IP\n"
    
    try:
        ipRes=client.iterator("/ip_addresses/{}/resolutions".format(ip))
        hosts="This IP found serving the following hosts:\n"
        for host in ipRes:
         hosts+=host.host_name +" at "+ datetime.isoformat(host.date)+'\n'
    except:
        pass
    return reputation,sslInfo,hosts
    
def main():
    argP=argparse.ArgumentParser(description="This tool is developed to help SOC analysts extracting Indicator of Attack from a suspicious email to check them agianst  OSINT resources")
    argP.add_argument("-p","--path",required=True,type=str,help=">>> Mandatory: the path of the eml file")
    argP.add_argument("-d","--dump",nargs='?',const='.',help=">>> Optional: dumps the attachments to the path you specify [or to the current directory if not specified] for more manual analysis")
    args=argP.parse_args()
    emlBinary,fileName=eml_grabber(args.path)
    emlClean=quo_cleaner(emlBinary)
    ips,urls,urlsFromSafeLink=extract_ioa(emlClean)
    nameHash=hash_ex(emlBinary,args.dump)
    isoDatetimes=datetimex(emlClean)
    hostNames=set(map(lambda x: urllib.parse.urlparse(x).hostname,urls))
    with open('api_keys.json','rt') as jsf:
        try:
            vtClient=vt.Client(json.load(jsf)["VT_api_key"])
        except:
            vtClient=None
    with open(fileName+'_anlysis.txt','wt') as o:
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
        o.write('\n*****************list of hostnems extracted*********************************\n\n')
        [o.write(hostname+'\n') for hostname in hostNames] 
        o.write('\n*************list of attachmnets and their filehashes extracted*************\n\n')
        [o.write(key+": {}\n".format(nameHash[key])) for key in nameHash.keys()]
        o.write('\n*****************list of timestamps extracted*******************************\n\n')
        [o.write(isodatetime+'\n') for isodatetime in isoDatetimes]
        o.write('\n****************************************************************************\n\
****************************************************************************\n')
        o.write("\n\nThanks for your support by using the tool! for any comments and issues please drop me a message on https://www.linkedin.com/in/moabdelrahman/ \n\n ")
    print("\nGreat!!! the IoAs extracted successfully please check {}_analysis.txt\n".format(fileName))
if __name__=='__main__':
    main()