<h1 align="center">PocOrExp in Github</h1>

<p align="center">
  <img      src="https://img.shields.io/badge/python-3.6-blue"/>
  <img      src="https://img.shields.io/github/stars/ycdxsb/PocOrExp_in_Github"/>  
  <img      src="https://img.shields.io/github/forks/ycdxsb/PocOrExp_in_Github"/> 
  <img      src="https://img.shields.io/github/issues/ycdxsb/PocOrExp_in_Github"/> 
  <img      src="https://img.shields.io/github/license/ycdxsb/PocOrExp_in_Github"/> 
</p>
<p align="center">
<img      src="https://img.shields.io/github/commit-activity/m/ycdxsb/PocOrExp_in_Github"/>
<img      src="https://img.shields.io/github/last-commit/ycdxsb/PocOrExp_in_Github"/>
</p>     

> 聚合Github上已有的Poc或者Exp，CVE信息来自CVE官网
>
> 注意：只通过通用的CVE号聚合，因此对于MS17-010等Windows编号漏洞以及著名的有绰号的漏洞，还是自己检索一下比较好

## Usage

```
python3 exp.py -h
usage: exp.py [-h]
              [-y {1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2011,2012,2013,2014,2015,2016,2017,2018,2019,2020,2021,all}]
              [-i {y,n}] [-w {y,n}]

CVE Details and Collect PocOrExp in Github

optional arguments:
  -h, --help            show this help message and exit
  -y {1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2011,2012,2013,2014,2015,2016,2017,2018,2019,2020,2021,all}, --year {1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2011,2012,2013,2014,2015,2016,2017,2018,2019,2020,2021,all}
                        get Poc or CVE of certain year or all years
  -i {y,n}, --init {y,n}
                        init or not
  -w {y,n}, --watch {y,n}
                        keep an eye on them or not
```
参数说明:
- -y指定处理某年的CVE
- -i说明是否为首次初始化，y表示初次，对于已处理的CVE不会处理，n表示否，会处理已处理的CVE
- -w监控PoC变化:当前策略为更新本年前的已知有PoC的CVE，以及本年的所有CVE

使用步骤：
- STEP1：安装依赖

  ```
  pip3 install tqdm aiohttp_requests
  ```

- STEP2：申请github api token写入项目目录下的TOKENS文件中，格式如下，可以使用多个token：

  ```
  token:your_token
  ```

- STEP3：处理cve信息

  ```
  python3 exp.py -y 2021 -i y
  python3 exp.py -y all -i y
  ```

- 如果想要加快速度，可使用异步版脚本exp_async.py

最终结果呈现在每个年份目录下的README.md，以及根目录下的PocOrExp.md中


## Log
- 20200411: 修改查询语句，从原来的模糊匹配转为严格匹配
- 20200412: 修改了github markdown渲染问题，~~可使用exp_markdown_for_github.py~~
- 20200412: 修复了github搜索时，例如搜索CVE-2020-3618，会搜索到CVE-2020-36184的结果的问题
- 20200412: 优化前缀搜索问题的处理方案
- 20200413: 由于NVD官网CVE编号缺失，改用CVE官网数据，发布异步版脚本
- 20200414: 完成第一轮PocOrExp的爬取，目前使用20个github api token，可以做到12小时内轮询所有CVE并更新
- 20200414: 做了一些简单数据统计，见[Statistics](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/Statistics/README.md)
- 20200416: 增加-w参数
- 20200417: 新增每日更新脚本today.py，更新内容见[Today](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/Today.md)，可以在上面修改，例如将`get_today_update`的返回结果通过server酱，wxpusher等发送给自己

## Reference
- https://github.com/nomi-sec/PoC-in-GitHub


