# zhixue_errorbook
智学网错题生成器  
 
## 注意：  
此项目使用Python3.8.7构建，不兼容Python2  
为维护方便，删除了release，请直接在code中下载erroebook.py    

## 需要引用的库  
  os,sys,typing,requests,json,hashlib,random,time,datetime,urllib,pillow,easygui  
 其中，requests,pillow,easygui库可能python没有预装，可以在终端内使用指令`pip install requests,pillow,easygui`安装    

## 使用方法    
* 安装Python3环境（我使用的是Python3.8.7）  
* 下载，运行errorbook.py  
* 输入用户名和密码登陆  
* 根据提示选择学科的id  
* 输入起止时间  
* 等待  
* 完成后将会在当前目录下放置生成好的html文档，可用浏览器打开，并使用CTRL+P键进行打印，也可以用word打开。  
  
## 已知问题  
~~*  登陆时输错密码会导致要求输入验证码，需要手动到网页里输入（这个项目总不可能带一个tf吧）~~  
  * 需要验证码时会弹窗要求输入验证码
* 推题功能请求过快会导致556错误，需要登陆教师账号，点击选题组卷后输入验证码。
  
## Tip  
为需要研究网络传输的小伙伴开头留下变量isVerifysslCert，可以指定是否验证证书有效性。  
如果软件报SSLError的话也请把这个变量改为False  

## 国内gitee镜像地址  
https://gitee.com/w2016561536/zhixue_errorbook
  
## 致谢  
https://blog.csdn.net/shadow20112011/article/details/102873995  ---   rc4加密   
https://github.com/mathjax/MathJax  ---  以优雅的方式在HTML文档中渲染Latex公式  
