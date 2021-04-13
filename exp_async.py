import json
import os
import shutil
import argparse
import datetime
import time
from random import sample
from tqdm import tqdm
import asyncio
import requests
from aiohttp_requests import requests as aio_requests
DOWNLOAD_DIR = 'download'
TOKEN_FILE = 'TOKENS'
tokens = []

def download_cve_xml(filename):
    base_url = "https://cve.mitre.org/data/downloads/"
    url = base_url + filename
    xml_content = requests.get(url, stream=True)
    with open(os.path.join(DOWNLOAD_DIR, filename), 'wb') as f:
        for chunk in xml_content:
            f.write(chunk)

def download_cve_xml_all():
    filenames = ["allitems-cvrf-year-%d.xml"%year for year in range(1999,datetime.datetime.now().year+1)]
    for filename in filenames:
        download_cve_xml(filename)
   
def parse_cve_xml(filename):
    with open(os.path.join(DOWNLOAD_DIR, filename),'rb') as f:
        content = f.read().split(b'\n')
    cve_infos = []
    cve_ids = []
    cve_descriptions = []
    for line in content:
        line = line.strip()
        if line.startswith(b"<CVE>"):
            cve_ids.append(line[5:-6].decode(encoding='utf-8'))
        if line.startswith(b'<Note Ordinal="1" Type="Description">'):
            cve_descriptions.append(line[37:-7].decode('utf-8','ignore'))
    cve_infos = []
    if(len(cve_ids)!=len(cve_descriptions)):
        print("error")
        return cve_infos
    else:
        for i in range(len(cve_ids)):
            cve_infos.append({'CVE_ID': cve_ids[i], 'CVE_DESCRIPTION': cve_descriptions[i]})
        return cve_infos
    
def generate_markdown_year(year):
    year = str(year)
    filenames = os.listdir(year)
    filenames = [filename for filename in filenames if filename.startswith('CVE')]
    cve_number = [[int(filename.split('.')[0].split('-')[-1]),filename] for filename in filenames]
    cve_number.sort( key=lambda e:e[0], reverse=True)
    string = []
    for number in cve_number:
        filename = os.path.join(year,number[1])
        print(filename)
        with open(filename,'r') as f:
            cve_info = json.load(f)
            if(cve_info['PocOrExp_NUM']==0):
                continue
            else:
                string.append("## %s" % cve_info['CVE_ID'])
                string.append("> %s\n" % cve_info['CVE_DESCRIPTION'])
                string.append("\n")
                for PocOrExp in cve_info['PocOrExp']:
                    URL = PocOrExp['URL']
                    AUTHOR = URL.split('/')[-2]
                    PROJECT_NAME = URL.split('/')[-1]
                    link = "- [%s](%s) : " % (URL,URL)
                    stars = "![starts](https://img.shields.io/github/stars/%s/%s.svg)" %(AUTHOR,PROJECT_NAME)
                    forks = "![forks](https://img.shields.io/github/forks/%s/%s.svg)" %(AUTHOR,PROJECT_NAME)
                    string.append(" ".join([link,stars,forks])+'\n')
    with open(os.path.join(year,"README.md"),'w') as f:
        tmp = "\n".join(string)
        tmp = tmp.replace("<","")
        tmp = tmp.replace(">","")
        f.write(tmp)
    return string

def generate_markdown():
    PocOrExps = []
    for year in list(range(1999, datetime.datetime.now().year+1))[::-1]:
        string = generate_markdown_year(year)
        PocOrExps.append('## %d' % year)
        PocOrExps = PocOrExps + string
        PocOrExps.append('\n')
    with open('PocOrExp.md','w') as f:
        tmp = '\n'.join(PocOrExps)
        tmp = tmp.replace("<","")
        tmp = tmp.replace(">","")
        f.write(tmp)

async def get_PocOrExp_in_github(CVE_ID,Other_ID = None,token=None):
    if(Other_ID == None):
        api = 'https://api.github.com/search/repositories?q="%s"&sort=stars' % CVE_ID
    else:
        api = 'https://api.github.com/search/repositories?q="%s" NOT "%s"&sort=stars' % (CVE_ID,Other_ID)
    
    windows = 0.6
    while(True):
        time.sleep(windows)
        headers = {"Authorization": "token "+token}
        req = await aio_requests.get(api,headers = headers)
        req = await req.text()
        req = json.loads(req)
        print(CVE_ID, req)
        if('items' in req):
            items = req['items']
            break
        else:
            token = sample(tokens,1)[0]
            windows += 0.1
    PocOrExps = []
    for item in items:
        URL = item['html_url']
        STARS_NUM = item['stargazers_count']
        FORKS_NUM = item['forks_count']
        DESCRIPTION = item['description']
        UPDATE_TIME = item['updated_at']
        PocOrExps.append({
            'URL': URL,
            'STARS_NUM': STARS_NUM,
            'FORKS_NUM': FORKS_NUM,
            'DESCRIPTION': DESCRIPTION,
            'UPDATE_TIME': UPDATE_TIME
        })
    return PocOrExps


def parse_arg():
    parser = argparse.ArgumentParser(
        description='CVE Details and Collect PocOrExp in Github')
    parser.add_argument('-y', '--year',required=False,default=None, choices=list(map(str,range(1999,datetime.datetime.now().year+1)))+['all'],
                        help="get Poc or CVE of certain year or all years")
    args = parser.parse_args()
    return args

def is_prefix(cve_ids,CVE_ID):
    for cve_id in cve_ids:
        if cve_id!= CVE_ID and cve_id.startswith(CVE_ID):
            return True
    return False

def get_all_startswith_CVE_ID(cve_ids,CVE_ID):
    result = []
    for cve_id in cve_ids:
        if cve_id!= CVE_ID and cve_id.startswith(CVE_ID):
            result.append(cve_id)
    return result

async def process_single_cve(cve_ids,item,token):
    CVE_ID = item['CVE_ID']
    year = item['CVE_ID'].split("-")[1]
    dump_file = os.path.join(year, CVE_ID + '.json')
    PocOrExps = []
    if(not is_prefix(cve_ids,CVE_ID)):
        PocOrExps = await get_PocOrExp_in_github(CVE_ID,None,token)
    else:
        PocOrExps = await get_PocOrExp_in_github(CVE_ID,None,token)
        if(len(PocOrExps)!=0):
            other_ids = get_all_startswith_CVE_ID(cve_ids,CVE_ID)
            PocOrExps = await get_PocOrExp_in_github(CVE_ID,None,token)
            for other_id in other_ids:
                tmp = await get_PocOrExp_in_github(CVE_ID,other_id,token)
                urls_CVE_ID = []
                urls_Other_ID = []
                for PocOrExp in PocOrExps:
                    urls_CVE_ID.append(PocOrExp['URL'])
                for PocOrExp in tmp:
                    urls_Other_ID.append(PocOrExp['URL'])
                urls_CVE_ID = list(set(urls_CVE_ID) & set(urls_Other_ID))
                tmp = PocOrExps
                PocOrExps = []
                for PocOrExp in tmp:
                    if(PocOrExp['URL'] in urls_CVE_ID):
                        PocOrExps.append(PocOrExp)
    cve_info = {}
    cve_info['CVE_ID'] = item['CVE_ID']
    cve_info['CVE_DESCRIPTION'] = item['CVE_DESCRIPTION']
    cve_info['PocOrExp_NUM'] = len(PocOrExps)
    cve_info['PocOrExp'] = PocOrExps
    with open(dump_file, 'w') as f:
        json.dump(cve_info, f)


def process_cve(cve_infos,cve_ids,init = True):
    tasks = []
    for i in range(len(cve_infos)):
        tasks.append(asyncio.ensure_future(process_single_cve(cve_ids,cve_infos[i],tokens[i])))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.wait(tasks)) 

def process_cve_year(year,init = True):
    filename = "allitems-cvrf-year-%d.xml"%year
    download_cve_xml(filename)
    cve_infos = parse_cve_xml(filename)
    cve_ids = []
    for item in cve_infos:
        cve_ids.append(item['CVE_ID'])
    tmp = []
    if(init):
        for item in cve_infos:
            CVE_ID = item['CVE_ID']
            year = item['CVE_ID'].split("-")[1]
            dump_file = os.path.join(year, CVE_ID + '.json')
            if(init and os.path.exists(dump_file)):
                continue
            else:
                tmp.append(item)
        cve_infos = tmp
    step = len(tokens)
    cve_infos_slice = [cve_infos[i:i+step] for i in range(0,len(cve_infos),step)]
    for cve_infos in tqdm(cve_infos_slice):
        process_cve(cve_infos,cve_ids,init)
    generate_markdown()
    
def process_cve_all(init = True):
    for year in list(range(1999,datetime.datetime.now().year+1))[::-1]:
        process_cve_year(year,init)

def init():
    if(os.path.exists(DOWNLOAD_DIR)):
        shutil.rmtree(DOWNLOAD_DIR)
    os.mkdir(DOWNLOAD_DIR)
    for year in range(1999, datetime.datetime.now().year+1):
        if(not os.path.exists(str(year))):
            os.mkdir(str(year))
    if(not os.path.exists(TOKEN_FILE)):
        print("please checkout your token files")
        exit(-1)
    global tokens
    with open(TOKEN_FILE) as f:
        content = f.readlines()
    for line in content:
        line = line.strip()
        if line.startswith("token:"):
            tokens.append(line.split(":")[-1])
    print(tokens)
    if(len(tokens)==0):
        print("please checkout your token files")
    
def main():
    args = parse_arg()
    init()
    print(args)
    if(args.year == "all"):
        process_cve_all()
    elif(args.year):
        process_cve_year(int(args.year))
    
    
if __name__=="__main__":
    main()
