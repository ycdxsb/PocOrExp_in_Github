import os
import subprocess

def parse_readme(content):
    d = {}
    i = 0
    CVE_ID = ""
    cve_ids = []
    for line in content:
        if line.startswith('## CVE'):
            CVE_ID = "CVE"+line.split('CVE')[-1]
            d[CVE_ID] = []
            cve_ids.append(CVE_ID)
        if line.startswith('- ['):
            url = line.split('[')[1].split(']')[0]
            d[CVE_ID].append(url)
    return d,cve_ids
         
def render_today(update):
    string = []
    for item in update:
        string.append("## %s"%item['CVE_ID'])
        for URL in item['PocOrExp']:
            AUTHOR = URL.split('/')[-2]
            PROJECT_NAME = URL.split('/')[-1]
            link = "- [%s](%s) : " % (URL,URL)
            stars = "![starts](https://img.shields.io/github/stars/%s/%s.svg)" %(AUTHOR,PROJECT_NAME)
            forks = "![forks](https://img.shields.io/github/forks/%s/%s.svg)" %(AUTHOR,PROJECT_NAME)
            string.append(" ".join([link,stars,forks]))
        string.append('\n')
        with open("Today.md",'w') as f:
            f.write("\n".join(string))
    return string

def get_today_update():
    status,output = subprocess.getstatusoutput('rm -rf PocOrExp_in_Github')
    status,output = subprocess.getstatusoutput('git clone https://github.com/ycdxsb/PocOrExp_in_Github.git')
    status,output = subprocess.getstatusoutput('cd PocOrExp_in_Github && git tag --sort=committerdate')
    tags = output.split('\n')
    print(tags)
    old_poc_or_exps = []
    new_poc_or_exps = []
    status,output = subprocess.getstatusoutput('cd PocOrExp_in_Github && git checkout %s' % tags[-2])
    with open('PocOrExp_in_Github/PocOrExp.md') as f:
        content = f.read().split('\n')
    content = [line for line in content if line!='']
    old_poc_or_exps,old_cve_ids = parse_readme(content)
    status,output = subprocess.getstatusoutput('cd PocOrExp_in_Github && git checkout %s' % tags[-1])
    with open('PocOrExp_in_Github/PocOrExp.md') as f:
        content = f.read().split('\n')
    content = [line for line in content if line!='']
    new_poc_or_exps,new_cve_ids = parse_readme(content)
    update = []
    for CVE_ID in new_cve_ids:
        if CVE_ID not in old_cve_ids:
            d = {}
            d['CVE_ID'] = CVE_ID
            d['PocOrExp'] = new_poc_or_exps[CVE_ID]
            update.append(d)
        else:
            old_urls = old_poc_or_exps[CVE_ID]
            new_urls = new_poc_or_exps[CVE_ID]
            diff = list(set(new_urls)-set(old_urls))
            if(len(diff)==0):
                continue
            d = {}
            d['CVE_ID'] = CVE_ID
            d['PocOrExp'] = []
            for url in new_urls:
                if url in diff:
                    d['PocOrExp'].append(url)
            update.append(d)
    return render_today(update)

if __name__=="__main__":
    update_today = get_today_update()

