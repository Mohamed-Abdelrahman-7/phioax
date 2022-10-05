import quopri,re,hashlib,email,os,urllib
from datetime import datetime

#function to load the eml from the path specified by the user 
def eml_grabber(pth):
    try:
        with open(pth,'rb') as f:
            eml=f.read()
            print("\nThe eml file is read successully, cleanining and parsing process is being initiated....")
            filename=os.path.split(f.name)[-1]
    except:
        print("Error while reading the file please make sure you provided  the correct path!!!")
    return eml,filename

# defining a fucntion to decode  quoted printable characters and return a clean version of the eml file
def quo_cleaner(eml):
    try:
        eml_clean=quopri.decodestring(eml)
    except:
        print("something went wrong while cleaning quoted printable characters")
    return eml_clean.decode(errors='ignore')

#function to extract public IPs and urls
def extract_IoA(eml_clean):
    IPs_ls=re.findall(r'(?:\d{1,3}\.){3}\d{1,3}',eml_clean)
    pub_IPs=[]
    for i in IPs_ls:
        if  i.startswith(("192.168.","10.","255.255.255.255")):
            continue
        elif  i.startswith("172") and 16<=int(i.split('.')[1])<32:
                continue
        elif any(int(x)>255 for x in i.split('.')):
            continue 
        else:
            pub_IPs.append(i)
    Urls=re.findall(r'https?://[^\s\"><]+',eml_clean)


    return set(pub_IPs),set(Urls)

#function to get a list of attachements and their corresponding file hashes [Optionally dump the attachments to your local storage]
def hashex(eml,dumppath):
    namehash={}
    msgobj=email.message_from_bytes(eml)
    for part in msgobj.walk():
        if part.get_content_disposition()=='multipart':
            continue
        filename=part.get_filename()
        if filename!=None:
            namehash[filename]=hashlib.sha256(part.get_payload(decode=True)).hexdigest()
            if dumppath != None:
                try:
                    with open(os.path.join(dumppath,filename),'wb') as f:
                     f.write(part.get_payload(decode=True))
                except:
                     print("an error occured while dumping{}!!! please check your write permission on the specified directory".format(filename))
    
    return namehash

# function to extract datetimes to detect any datetime anomlaies
def datetimex(eml):
   R_datimes= re.findall(r'(?<=Received)[^;]*;[^\d]+(.+\d)',eml)
   D_datetime=re.findall(r'(?<=Date)[^,]*,[^\d]+(.+\d)',eml)
   isodatetimes=[]
   for i in R_datimes:
     try:
        isodatetimes.append(datetime.strptime(i,"%d %b %Y %H:%M:%S %z").isoformat())
     except:
        continue
   for j in D_datetime:
    try:
            isodatetimes.append(datetime.strptime(j,"%d %b %Y %H:%M:%S %z").isoformat())
    except:
            continue
   return isodatetimes


def main():
    import argparse
    argp=argparse.ArgumentParser(description="This program is developed to help SOC analysts extracting Indicator of Attack from a suspicious email and check them agianst comon OSINT")
    argp.add_argument("-p","--path",required=True,type=str,help=">>> Mandatory: the path of the eml file")
    argp.add_argument("-d","--dump",nargs='?',const='.',help=">>> Optional: dumps the attachments to the path you specify [or to the current directory if not specified] for more manual analysis")
    args=argp.parse_args()
    print(args.path)
    eml_binary,filename=eml_grabber(args.path)
    eml_clean=quo_cleaner(eml_binary)
    ips,urls=extract_IoA(eml_clean)
    namehash=hashex(eml_binary,args.dump)
    isodatetimes=datetimex(eml_clean)
    hostnames=set(map(lambda x: urllib.parse.urlparse(x).hostname,urls))
    with open(filename+'_anlysis.txt','wt') as o:
        o.write("*********************list of IPs extracted***********************************\n\n")
        [o.write(ip+'\n') for ip in ips ]
        o.write('\n*******************list of URLs extracted***********************************\n\n')
        [o.write(url+'\n') for url in urls]
        o.write('\n*****************list of hostnems extracted*********************************\n\n')
        [o.write(hostname+'\n') for hostname in hostnames] 
        o.write('\n*************list of attachmnets and their filehashes extracted*************\n\n')
        [o.write(key+": {}\n".format(namehash[key])) for key in namehash.keys()]
        o.write('\n*****************list of timestamps extracted*******************************\n\n')
        [o.write(isodatetime+'\n') for isodatetime in isodatetimes]
        o.write("\n\n Thanks for using the program for any comments and issues please drop me a message on https://www.linkedin.com/in/moabdelrahman/ \n\n ")
    print("\nGreat!!! the IoAs extracted successfully please check {}_analysis.txt\n".format(filename))

if __name__=='__main__':
    main()

