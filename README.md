<h1 align="center">PocOrExp in Github</h1>

<p align="center">
  <img      src="https://visitor-badge.glitch.me/badge?page_id=https://github.com/ycdxsb/PocOrExp_in_Github/README.md"/>
  <img      src="https://img.shields.io/github/stars/ycdxsb/PocOrExp_in_Github"/>  
  <img      src="https://img.shields.io/github/forks/ycdxsb/PocOrExp_in_Github"/> 
  <img      src="https://img.shields.io/github/issues/ycdxsb/PocOrExp_in_Github"/> 
  <img      src="https://img.shields.io/github/license/ycdxsb/PocOrExp_in_Github"/> 
</p>
<p align="center">
<img      src="https://img.shields.io/github/commit-activity/m/ycdxsb/PocOrExp_in_Github"/>
<img      src="https://img.shields.io/github/last-commit/ycdxsb/PocOrExp_in_Github"/>
<img      src="https://img.shields.io/github/repo-size/ycdxsb/PocOrExp_in_Github"/>
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

## PocOrExps
- [PocOrExp All](https://github.com/ycdxsb/PocOrExp_in_Github/blob/main/PocOrExp.md)
- [2021](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2021/README.md)
- [2020](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2020/README.md)
- [2019](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2019/README.md)
- [2018](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2018/README.md)
- [2017](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2017/README.md)
- [2016](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2016/README.md)
- [2015](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2015/README.md)
- [2014](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2014/README.md)
- [2013](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2013/README.md)
- [2012](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2012/README.md)
- [2011](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2011/README.md)
- [2010](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2010/README.md)
- [2009](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2009/README.md)
- [2008](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2008/README.md)
- [2007](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2007/README.md)
- [2006](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2006/README.md)
- [2005](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2005/README.md)
- [2004](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2004/README.md)
- [2003](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2003/README.md)
- [2002](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2002/README.md)
- [2001](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2001/README.md)
- [2000](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/2000/README.md)
- [1999](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/1999/README.md)

## Log
- 20200412: 修复了github搜索时，例如搜索CVE-2020-3618，会搜索到CVE-2020-36184的结果的问题
- 20200413: 由于NVD官网CVE编号缺失，改用CVE官网数据，发布异步版脚本
- 20200414: 完成第一轮PocOrExp的爬取，目前使用20个github api token，可以做到12小时内轮询所有CVE并更新
- 20200414: 做了一些简单数据统计，见[Statistics](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/Statistics/README.md)
- 20200416: 增加-w参数
- 20200417: 新增每日更新脚本today.py，更新内容见[Today](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/Today.md)，可以在上面修改，例如将`get_today_update`的返回结果通过server酱，wxpusher等发送给自己
- 20200420: 发现一些非PoC的repo, 通过增加黑名单去除，同时更新异步脚本v2。
- 20200423: 发现今日更新的结果里有的repo并不是近期更新的，原因如下：
  - 1. repo从private转public
  - 2. 通过api查询时，脚本策略为取star数目前30的结果，因此当同一CVE的其他repo数目增加时，会进入前30列表中，表现为今日新增。统计发现按照CVE号搜索结果超过100的大洞只有CVE-2019-0708，因此不使用分页爬取所有，修改为每次取star数目前100的结果。
- 20200430: [download](https://github.com/ycdxsb/PocOrExp_in_Github/tree/main/download.py)下载所有PoC/Exp，防止repo被发布者删除

## Reference
- https://github.com/nomi-sec/PoC-in-GitHub


