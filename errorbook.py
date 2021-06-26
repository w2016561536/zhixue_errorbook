
import datetime
import hashlib
import json
import os
import random
import sys
import time
import urllib
from typing import Pattern, SupportsRound
import easygui
import requests
from requests import cookies, utils
from requests.api import head, request
from requests.models import Response
from requests.sessions import Session, session

isVerifysslCert = False  # 需要网络调试请改为False
requestdelay = 8  # 教师账号推题请求延时，单位秒
global needsaveuseranswer
needsaveuseranswer = True  # 是否保存自己的错误答案
config_stu_name = ""  # 配置默认学生账号密码，留空代表每次询问
config_stu_pwd = ""

editheaders = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6'

}
global headerforerrbook
headerforerrbook = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'authbizcode': '100000000',
    'authtimestamp': '',
    'authguid': '',
    'authtoken': '',
    'XToken': 'null'
}

# rc4加密，来源于https://blog.csdn.net/shadow20112011/article/details/102873995


def bytesToHex(bytes):
    sb = ''
    for i in range(len(bytes)):
        hexs = hex(bytes[i] & 0xFF)[2:]
        if len(hexs) < 2:
            sb += '0'
        sb += hexs
    return sb


def hexToByte(inHex):
    hexlen = len(inHex)
    result = []
    if (hexlen % 2 == 1):
        hexlen += 1
        inHex = "0"+inHex
    for i in range(0, hexlen, 2):
        result.append(int(inHex[i:i+2], 16))
    return result


def initKey(aKey):
    state = list(range(256))
    bkey = [ord(i) for i in list(aKey)]
    index1 = 0
    index2 = 0
    if (len(bkey) == 0):
        return []
    for i in range(256):
        index2 = ((bkey[index1] & 0xff) + (state[i] & 0xff) + index2) & 0xff
        state[i], state[index2] = state[index2], state[i]
        index1 = (index1 + 1) % len(bkey)
    return state


def RC4Base(input, mKkey):
    x = 0
    y = 0
    key = initKey(mKkey)
    result = list(range(len(input)))
    for i in range(len(input)):
        x = (x + 1) & 0xff
        y = ((key[x] & 0xff) + y) & 0xff
        key[x], key[y] = key[y], key[x]
        xorIndex = ((key[x] & 0xff) + (key[y] & 0xff)) & 0xff
        result[i] = (input[i] ^ key[xorIndex])
    return result


def encryRC4Byte(data, key, chartSet='utf-8'):
    if not chartSet:
        bData = [ord(i) for i in data]
        return RC4Base(bData, key)
    else:
        bData = list(data.encode(chartSet))
        return RC4Base(bData, key)


def decryRC4(data, key, chartSet='utf-8'):
    r = RC4Base(hexToByte(data), key)
    return bytes(r).decode(chartSet)


def encryRC4String(data, key, chartSet='utf-8'):
    return bytesToHex(encryRC4Byte(data, key, chartSet))

# rc4加密方法结束


# 3-16 分割 补齐

def divideStringtoHex(str5):
    if len(str5) % 2 == 1:
        str1 = "0" + str5
    else:
        str1 = str5
    hexArray = []
    i = 0
    while (i < len(str1)):
        hexArray.append(str1[i:i+2])
        i += 2
    while (hexArray[0] == "00" or hexArray[0] == "0"):
        del hexArray[0]
    i = len(hexArray)-1
    while (i >= 0 and hexArray[i] == "00"):
        del hexArray[i]
        i -= 1
    return hexArray


patterner = "123456789abcde"


def paddind(fHexArray: list, keylen: int):
    if (len(fHexArray)) > keylen:
        print("密码过长，可能是智学网修改了算法")
        input("回车退出程序")
        exit()
    fHexArray.append("00")
    i = len(fHexArray)
    while (i <= keylen-3):
        appendstr = str(patterner[random.randint(0, 13)]) + \
            str(patterner[random.randint(0, 13)])
        fHexArray.append(appendstr)
        i += 1
    fHexArray.extend(["02", "00"])
    return fHexArray


def relogin(username, typepwd, isrelogin, moreinfo):
    print("正在尝试重新登陆")
    msg = loginwithpwd(username, typepwd, isrelogin, moreinfo)
    return msg


def download_img(sessions: Session, url):
    # 下载图片
    r = sessions.get(url, stream=True)
    locate = './img_{}.png'.format(0)
    if r.status_code == 200:
        open(locate, 'wb').write(r.content)  # 将内容写入图片
    del r
    return locate


def loginwithpwd(username, typepwd, isrelogin, moreinfo):
    # rc4-登陆
    weakpwdsession = requests.Session()
    password = encryRC4String(typepwd, "iflytzhixueweb", chartSet='utf-8')
    loginstatue = weakpwdsession.get(
        "https://www.zhixue.com/loginState/", verify=isVerifysslCert, headers=editheaders)
    casUrl = loginstatue.json()["casUrl"]
    serviceUrl = loginstatue.json()["serviceUrl"]
    #weakpwdsession.cookies = loginstatue.cookies
    weakpwdsession.cookies["loginUserName"] = username
    weaklogin = weakpwdsession.post("https://www.zhixue.com/weakPwdLogin/?from=web_login",
                                    verify=isVerifysslCert,
                                    headers=editheaders,
                                    data="loginName=" + username + "&password=" +
                                    password + "&description=encrypt" + moreinfo,
                                    cookies=weakpwdsession.cookies)
    resforweaklogin = weaklogin.json()
    if resforweaklogin["result"] == "success":
        # print(resforweaklogin["data"])
        weakpwdsession.cookies["ui"] = resforweaklogin["data"]
    else:
        if (resforweaklogin["message"].index("验证码")) != -1:
            isrelogin = 0
        if isrelogin == 0:
            print("登陆失败："+resforweaklogin["message"])
            if (resforweaklogin["message"].index("验证码")) != -1:
                uuid = makeauthtoken()[1]
                locate = download_img(
                    weakpwdsession, "https://www.zhixue.com/login/forgetpwd/getImageCode??token=0.668465465484&uuid="+uuid)
                yzm = easygui.enterbox(msg="请输入验证码", image=locate)
                isrelogin = 0
            msg = relogin(username, typepwd, isrelogin+1,
                          "&code=" + yzm + "&uuid="+uuid)
            return msg
        elif isrelogin == 1:
            print("登陆失败："+resforweaklogin["message"])
            anme = input("登陆失败，请重新输入用户名尝试：")
            pwd = input("请重新输入密码：")
            msg = relogin(anme, pwd, isrelogin+1, "")
            return msg
        else:
            print("登陆失败："+resforweaklogin["message"])
            input("回车退出程序")
            exit()

    # rc4 登陆结束

    # 中央认证
    # 创建认证
    makeloginreq = weakpwdsession.post("https://www.zhixue.com/log/userActionLog/create",
                                       verify=isVerifysslCert,
                                       headers=editheaders, cookies=weakpwdsession.cookies,
                                       data="success=success&account=" + username + "&module=rq_web_login&opCode=1005&userId=" +
                                       resforweaklogin["data"] + "&sessionId=" +
                                       loginstatue.cookies["tlsysSessionId"]
                                       )
    if makeloginreq.json()["errorCode"] != 0:
        if isrelogin == 0:
            print("出错了！！\n响应码："+str(makeloginreq.json()["errorCode"]))
            msg = relogin(username, typepwd, isrelogin+1, "")
            return msg
        elif isrelogin == 1:
            print("出错了！！\n响应码："+str(makeloginreq.json()["errorCode"]))
            anme = input("登陆失败，请重新输入用户名尝试：")
            pwd = input("请重新输入密码：")
            msg = relogin(anme, pwd, isrelogin+1, "")
            return msg
        else:
            print("出错了！！\n响应码："+str(makeloginreq.json()["errorCode"]))
            input("回车退出程序")
            exit()

    # 获取LT
    centrallogin = requests.Session()
    LTres = centrallogin.get(
        casUrl+"sso/login?sso_from=zhixuesso&service=" + serviceUrl, verify=isVerifysslCert, cookies=centrallogin.cookies)

    LTrawtaext = LTres.text
    firstplace = int(LTrawtaext.find(r"('")+2)
    lastplace = int(LTrawtaext.rfind(r"')"))
    LTrawtaext = LTrawtaext[firstplace:lastplace]
    LTrawtaext = LTrawtaext.replace("\\", "")  # json化
    # print(LTrawtaext)
    LT_JSON = json.loads(LTrawtaext)
    # print(LT_JSON["data"]["lt"].encode().hex())
    LT = LT_JSON["data"]["lt"]
    execution = LT_JSON["data"]["execution"]
    # .encode().hex()
    # 构造RSA密码
    makepwd = str("LT/" + LT + "/" + typepwd).encode().hex()
    beforehexpwd = divideStringtoHex(makepwd)
    beforehexpwd = paddind(beforehexpwd, 128)
    beforehexpwd.reverse()
    makepwd = "".join(beforehexpwd)
    intpwd = int(makepwd, 16)
    encriedpwd = pow(intpwd, 65537, 143846244081099508648901372746659280006302505545479331274243675556721429123147854452215976399432374678014518658921467308832595550803689495835386150764953813095542106389384340697062624656038387147042232009506827653295712113445432238581040988464470584322208115885076367065603239952069923435605267625944018546121)
    #hexpwd = hex(encriedpwd)[2:]
    # 登陆
    Ticketreq = centrallogin.get(casUrl+"sso/login?sso_from=zhixuesso&service=" + serviceUrl +
                                 "&encode=true&sourceappname=tkyh%2Ctkyh&_eventId=submit&appId=zx-container-client&client=web&type=loginByNormal&key=auto&lt=" + LT + "&execution="+execution + "&customLogoutUrl=https%3A%2F%2Fwww.zhixue.com%2Flogin.html&ncetAppId=QLIqXrxyxFsURfFhp4Hmeyh09v6aYTq1&sysCode=&username=" + username + "&encodeType=R2%2FP%2FLT&password=" + hex(encriedpwd)[2:], verify=isVerifysslCert, cookies=centrallogin.cookies)
    stRawText = Ticketreq.text
    firstplace = int(stRawText.find(r"('")+2)
    lastplace = int(stRawText.rfind(r"')"))
    stRawText = stRawText[firstplace:lastplace]
    stRawText = stRawText.replace("\\", "")  # json化
    st_json = json.loads(stRawText)
    result = st_json["code"]
    if result == 1001:
        # print("登陆成功")
        st_ticket = st_json["data"]["st"]
    else:
        if isrelogin == 0:
            print("登陆失败：" + "\n响应码：" + str(result) +
                  "\n信息：" + st_json["message"])
            msg = relogin(username, typepwd, isrelogin+1, "")
            return msg
        elif isrelogin == 1:
            print("登陆失败：" + "\n响应码：" + str(result) +
                  "\n信息：" + st_json["message"])
            anme = input("登陆失败，请重新输入用户名尝试：")
            pwd = input("请重新输入密码：")
            msg = relogin(anme, pwd, isrelogin+1, "")
            return msg
        else:
            print("登陆失败：" + "\n响应码：" + str(result) +
                  "\n信息：" + st_json["message"])
            input("回车退出程序")
            exit()
    # 中央认证结束
    # 向智学网提交st
    verfiylogin = weakpwdsession.post(serviceUrl, data="action=login&ticket=" +
                                      st_ticket, verify=isVerifysslCert, cookies=weakpwdsession.cookies, headers=editheaders)
    if verfiylogin.text.index("success") != -1:
        print("登陆完成")

    timestamp = str(int(time.time() * 1000))
    getCurrentuser = weakpwdsession.get("https://www.zhixue.com/apicourse/web/getCurrentUser?token=&t=" +
                                        timestamp, verify=isVerifysslCert, headers=editheaders, cookies=weakpwdsession.cookies)

    userinfo = json.loads(getCurrentuser.text)
    if userinfo["errorCode"] == 0 and userinfo["errorInfo"] == "操作成功":
        print("获取用户信息成功！\n用户id：" + userinfo["result"]["currentUser"]
              ["loginName"]+"\n用户名：" + userinfo["result"]["currentUser"]["name"])
    else:

        if isrelogin == 0:
            print("登陆失败：" + "\n响应码：" +
                  str(userinfo["errorCode"]) + "\n信息：" + userinfo["errorInfo"])
            msg = relogin(username, typepwd, isrelogin+1, "")
            return msg
        elif isrelogin == 1:
            print("登陆失败：" + "\n响应码：" +
                  str(userinfo["errorCode"]) + "\n信息：" + userinfo["errorInfo"])
            anme = input("登陆失败，请重新输入用户名尝试：")
            pwd = input("请重新输入密码：")
            msg = relogin(anme, pwd, isrelogin+1, "")
            return msg
        else:
            print("登陆失败：" + "\n响应码：" +
                  str(userinfo["errorCode"]) + "\n信息：" + userinfo["errorInfo"])
            input("回车退出程序")
            exit()

    # 获取用户信息结束
    return [weakpwdsession, userinfo["result"]["currentUser"]["loginName"], userinfo["result"]["currentUser"]["name"]]


def md5cacu(texts):
    hl = hashlib.md5()
    hl.update(texts.encode("utf-8"))
    return hl.hexdigest()


def makeauthtoken():
    authtimestamp = str(int(time.time() * 1000))
    authguid = ""
    i = 0
    while i < 36:
        authguid += patterner[random.randint(0, 13)]
        i += 1
    authguid = list(authguid)
    authguid[14] = "4"
    place = int(3 & int(authguid[19].encode().hex(), 16) | 8)
    authguid[19] = "0123456789abcdef"[place: place + 1]
    authguid[8] = authguid[13] = authguid[18] = authguid[23] = "-"
    authguid = "".join(authguid)
    authtoken = md5cacu(authguid+authtimestamp+"zxw?$%999userpwd")
    return [authtimestamp, authguid, authtoken]

# 获取Xtoken


def re_fresh_auth_token(heraders):
    authtoken = makeauthtoken()
    heraders["authtimestamp"] = authtoken[0]
    heraders["authguid"] = authtoken[1]
    heraders["authtoken"] = authtoken[2]


def getxtoken(session: Session):
    re_fresh_auth_token(headerforerrbook)
    resforindex = session.get("https://www.zhixue.com/addon/error/book/index",
                              verify=isVerifysslCert, headers=headerforerrbook, cookies=session.cookies)
    resforindex = resforindex.text
    resforindex = json.loads(resforindex)
    if resforindex["errorCode"] == 0:
        return resforindex["result"]
    else:
        print("登陆超时：" + "\n响应码：" +
              str(resforindex["errorCode"]) + "\n信息：" + resforindex["errorInfo"])
        input("回车退出程序")
        exit()


def timecovent(timestamp: str):
    timeArray = time.localtime(int(str(timestamp)[:-3]))
    otherStyleTime = time.strftime("%Y-%m-%d", timeArray)
    return otherStyleTime


def geterrorlists(session: Session, subject: str, begintime: str, endtime: str, gradecode: str, hardcount: int, easycount: int, subjectname: str, teachers: Session, requiresametype: bool, tchlist: list):
    re_fresh_auth_token(headerforerrbook)
    rawrespond = session.get("https://www.zhixue.com/addon/app/errorbook/getErrorbookList?subjectCode=" +
                             subject+"&beginTime="+begintime+"&endTime="+endtime+"&pageIndex=1&pageSize=10", headers=headerforerrbook, verify=isVerifysslCert, cookies=session.cookies)
    rawrespond = json.loads(rawrespond.text)
    if rawrespond["errorCode"] != 0:
        print("登陆超时：" + "\n响应码：" +
              str(rawrespond["errorCode"]) + "\n信息：" + rawrespond["errorInfo"])
        input("回车退出程序")
        exit()
    pages: list = rawrespond["result"]["pageInfo"]["allPages"]
    if len(pages) == 0:
        input("无错题")
        exit()
    del pages[0]
    fstart = 0
    if len(subject) == 1:
        subject = "0" + subject
    for switchtch in tchlist:
        switchtch = switchtch[0]
        if isinstance(switchtch, str) == False:
            changesub = switchtch.post("https://www.zhixue.com/paperfresh/api/common/switchSubject",
                                       data="phaseCode=05&subjectCode="+subjectcode, verify=isVerifysslCert, headers=editheaders)
            time.sleep(requestdelay/len(tchAccount))
            while changesub.status_code != 200:
                input("出错了：状态码：" + str(changesub.status_code))
                changesub = switchtch.post("https://www.zhixue.com/paperfresh/api/common/switchSubject",
                                           data="phaseCode=05&subjectCode="+subjectcode, verify=isVerifysslCert, headers=editheaders)
                time.sleep(requestdelay/len(tchAccount))
            changesub = json.loads(changesub.text)
            throwerror(changesub)

    htmltext = "<html><haed><meta charset=\"utf-8\"></head><body><style>p{Margin:0px;}</style><p align=center style='text-align:center'><span style='font-size:22.0pt;mso-bidi-font-size:24.0pt'><strong>" + \
        username + "的" + subjectname + "错题本</strong></span></p><br>"
    processed = processerrorbook(
        rawrespond, fstart, gradecode, hardcount, easycount, teachers, requiresametype)
    htmltext += processed[0]
    fstart = processed[1]
    for page in pages:
        re_fresh_auth_token(headerforerrbook)
        rawrespond = session.get("https://www.zhixue.com/addon/app/errorbook/getErrorbookList?subjectCode=" +
                                 subject+"&beginTime="+begintime+"&endTime="+endtime+"&pageIndex=" + str(page) + "&pageSize=10", headers=headerforerrbook, verify=isVerifysslCert)
        rawrespond = json.loads(rawrespond.text)
        if rawrespond["errorCode"] != 0:
            print("登陆超时：" + "\n响应码：" +
                  str(rawrespond["errorCode"]) + "\n信息：" + rawrespond["errorInfo"])
            input("回车退出程序")
            exit()
        processed = processerrorbook(
            rawrespond, fstart, gradecode,  hardcount, easycount, teachers, requiresametype)
        htmltext += processed[0]
        fstart = processed[1]
    return htmltext


def switch_tch(tchlist: list, usingtch: Session, usinginfo: list):
    totalcount = len(tchlist)
    nowcount = tchlist.index(usinginfo)
    if nowcount + 1 < totalcount:
        usingtch = tchlist[nowcount+1][0]
        usinginfo = tchlist[nowcount+1]
    else:
        usingtch = tchlist[0][0]
        usinginfo = tchlist[0]

    return usingtch


def getsubject(session: Session):
    re_fresh_auth_token(headerforerrbook)
    rawrespond = session.get("https://www.zhixue.com/addon/app/errorbook/getSubjects",
                             headers=headerforerrbook, verify=isVerifysslCert)
    rawrespond = json.loads(rawrespond.text)
    subdict = {}
    if rawrespond["errorCode"] != 0:
        print("登陆超时：" + "\n响应码：" +
              str(rawrespond["errorCode"]) + "\n信息：" + rawrespond["errorInfo"])
        input("回车退出程序")
        exit()
    subjects = rawrespond["result"]["subjects"]
    for subject in subjects:
        subdict[str(subject["code"])] = str(subject["name"])
    for key, value in subdict.items():
        print('{key}:{value}'.format(key=key, value=value))
    return subdict


def writefile(aaaa, filename: str):
    with open(os.path.join(os.path.abspath(""), filename), "w+", encoding='utf-8') as f:
        f.write(str(aaaa))
        f.close()
    filepaths = os.path.join(os.path.abspath(""), filename)
    return filepaths


def processerrorbook(sourceerror, startfrom: int, gradecode: str, hardcount: int, easycount: int, teachers: Session, requireSametype: bool):

    before = "<p style='Margin:0px'><strong>第"
    errorbooklist = sourceerror["result"]["wrongTopics"]["list"]
    htmltext = ""
    questionlists = []
    analysislists = []
    useranswerlist = []
    answerlist = []
    source = []
    answertime = []
    questionorder = []
    difficultlist = []
    knowledgelist = []
    questiontypelist = []
    smalltopicnumber = []
    ismulti = []
    for question in errorbooklist:
        question = question["errorBookTopicDTO"]
        questionlists.append(question["contentHtml"].replace("\\", ""))
        analysislists.append(question["analysisHtml"].replace("\\", ""))
        answerlist.append(question["answerHtml"].replace("\\", ""))
        if "isMulti" in question["wrongTopicRecordArchive"]:
            ismulti.append(question["wrongTopicRecordArchive"]["isMulti"])
        else:
            ismulti.append(False)
        smalltopicnumber.append(
            question["wrongTopicRecordArchive"]["smallTopicNumber"])
        answertime.append(
            question["wrongTopicRecordArchive"]["userAnswerTime"])
        source.append(question["wrongTopicRecordArchive"]["topicSetName"])
        questionorder.append(question["order"])
        difficultlist.append(
            str(question["wrongTopicRecordArchive"]["difficultyValue"]))
        knowledgelist.append(
            question["wrongTopicRecordArchive"]["knowledgeIds"])
        if "topicType" in question["wrongTopicRecordArchive"]:
            questiontypelist.append(
                str(question["wrongTopicRecordArchive"]["topicType"]))
        else:
            questiontypelist.append("00")
        if "imageAnswers" in question["wrongTopicRecordArchive"]:
            useranswerlist.append(
                question["wrongTopicRecordArchive"]["imageAnswers"])
        else:
            useranswerlist.append(
                question["wrongTopicRecordArchive"]["userAnswer"])
    lastorder = -1
    if needsaveuseranswer == False:
        i = 0
        while i < len(useranswerlist):
            useranswerlist[i] = ""
            i += 1
    for i in range(0, len(questionlists)):
        needmoreinfo = 1
        if startfrom+questionorder[i] == lastorder and ismulti[i] == True:
            htmltext += before + \
                str(startfrom+questionorder[i]) + "-" + \
                str(smalltopicnumber[i]) + "题&nbsp;</strong></p>"
            needmoreinfo = 0
            # htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;解析</span></p>"
            #htmltext += analysislists[i]
        elif startfrom+questionorder[i] != lastorder and ismulti[i] == True:
            htmltext += before + str(startfrom+questionorder[i]) + "-" + str(
                smalltopicnumber[i]) + "题&nbsp;</strong>来源：" + source[i] + "&nbsp;&nbsp;&nbsp;答题时间：" + timecovent(answertime[i]) + "</p>"
            htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;错题题目</span></p>"
            htmltext += loop_clear_expires(questionlists[i])
            htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;解析</span></p>"
            htmltext += loop_clear_expires(analysislists[i])
            needmoreinfo = 1
        else:
            htmltext += before + str(startfrom+questionorder[i]) + "题&nbsp;</strong>来源：" + \
                source[i] + "&nbsp;&nbsp;&nbsp;答题时间：" + \
                timecovent(answertime[i]) + "</p>"
            htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;错题题目</span></p>"
            htmltext += loop_clear_expires(questionlists[i])
            htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;解析</span></p>"
            htmltext += loop_clear_expires(analysislists[i])
            needmoreinfo = 1
        if needsaveuseranswer == True:
            htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;我的答案</span></p>"
        if isinstance(useranswerlist[i], list):
            for pic in useranswerlist[i]:
                htmltext += loop_clear_expires("<img src=\""+pic+"\"><br>")
        else:
            htmltext += loop_clear_expires(useranswerlist[i])
        htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;参考答案</span></p>"
        htmltext += answerlist[i]
        if easycount > 0 or hardcount > 0 and isinstance(teachers, str) == False and needmoreinfo == 1:
            if requireSametype == False:
                questiontypelist[i] = ""
            htmltext += r"<p style='background:#DBDBDB;Margin:0px'><span style='color:green'>&nbsp;&nbsp;&nbsp;&nbsp;推题</span></p>"
        if easycount > 0:
            htmltext += read_question(teachers, difficultlist[i], knowledgelist[i],
                                      subjectcode, questiontypelist[i], gradecode, easycount)
        if hardcount > 0 and isinstance(teachers, str) == False and needmoreinfo == 1:
            temphtml = read_question(
                teachers, "5", knowledgelist[i], subjectcode, questiontypelist[i], gradecode, hardcount)
            if len(temphtml) < 5:
                temphtml = read_question(
                    teachers, "4", knowledgelist[i], subjectcode, questiontypelist[i], gradecode, hardcount)
            htmltext += temphtml
        #htmltext+= str(needmoreinfo)
        htmltext += "<br><br><br><br>"
        lastorder = startfrom+questionorder[i]
    startfrom += questionorder[-1]
    return [htmltext, startfrom]


def covent_img_to_latex(htmlstr: str):
    spacearray = []
    img_position = 0
    lastposition = 0
    while htmlstr.find("<img ", lastposition) != -1:
        img_position = htmlstr.find("<img ", lastposition)
        lastposition = htmlstr.find(">", img_position)
        spacearray.append([img_position, lastposition,
                           htmlstr[img_position:lastposition]])
    arrayorder = 0
    while arrayorder < len(spacearray):
        if str(spacearray[arrayorder][2]).lower().find("data-latex=\"") == -1:
            del spacearray[arrayorder]
        else:
            latextext = str(spacearray[arrayorder][2])
            frontkey = latextext.lower().find("data-latex=\"") + 12
            lastkey = latextext.lower().find("\"", frontkey)
            spacearray[arrayorder][2] = urllib.parse.unquote(
                latextext[frontkey:lastkey])
            arrayorder += 1
    arrayorder = len(spacearray) - 1
    while arrayorder >= 0:
        htmlstr = htmlstr[0:spacearray[arrayorder][0]] + \
            "\\(" + spacearray[arrayorder][2] + "\\)" + \
            htmlstr[spacearray[arrayorder][1]+1:]
        arrayorder -= 1
    return htmlstr


def arrangelist(problemlist: list):
    htmltext = ""
    if len(problemlist) > 0:
        for a in problemlist:
            difficulty = a["difficulty"]["name"]
            htmltext += "<p><strong>题目：("+difficulty+")</strong></p>"
            htmltext += a["originalStruct"]["contentHtml"]
            htmltext += "<p><strong>解析：</strong></p>"

            if a["originalStruct"]["analysisHtml"] == "":
                htmltext += "<img src=\"" + a["analysisImg"] + "\">"
            else:
                htmltext += a["originalStruct"]["analysisHtml"]

            htmltext += "<p><strong>答案：</strong></p>"
            if a["originalStruct"]["answerHtml"] == "":
                htmltext += "<img src=\"" + a["answerImg"] + "\">"
            else:
                htmltext += a["originalStruct"]["answerHtml"]+"<br>"
    return htmltext


def throwerror(respon: dict):
    if respon["errorCode"] != 0:
        print("出现错误，" + "\n响应码：" +
              str(respon["errorCode"] + "\n错误信息：" + str(respon["errorInfo"])))
        input("按回车键退出程序")
        exit()


def coventlist(rawlist: list):
    returnstr = "["
    if len(rawlist) > 0:
        for a in rawlist:
            returnstr += "\""+str(a) + "\","
        returnstr = returnstr[:-1] + "]"
        return returnstr


def clear_expires(sourcestr: str):
    front = sourcestr.find("&Expires=")
    if front == -1:
        front = sourcestr.find("Expires=")
    if front == -1:
        return sourcestr
    else:
        behiend = sourcestr.find("&", front+1)
        if behiend == -1:
            behiend = ""
        if sourcestr[front] == "&":
            if isinstance(behiend, int) == True:
                return sourcestr[0:front] + sourcestr[behiend:]
            else:
                return sourcestr[0:front]
        else:
            if isinstance(behiend, int) == True:
                return sourcestr[0:front] + sourcestr[behiend+1:]
            else:
                return sourcestr[0:front]


def loop_clear_expires(sourcehtml: str):
    tempresult = sourcehtml
    while tempresult != clear_expires(tempresult):
        tempresult = clear_expires(tempresult)
    return tempresult


def read_question(teacher: Session, difficulty: str, knowledgeid: list, subjectscode: str, questiontype: str, gradecode: str, counts: int):
    difficulty = int(difficulty)
    difficulty = "0" + str(6-difficulty)
    if len(subjectscode) == 1:
        subjectscode = "0" + subjectscode
    if len(questiontype) == 1:
        questiontype = "0" + questiontype
    if len(gradecode) == 1:
        gradecode = "0" + gradecode
    # 这里定义了无视难度
    difficulty = "01;02;03"
    # print(u_tch_info[1],u_tch_info[2])
    firstget = using_tch_session.get("https://www.zhixue.com/paperfresh/api/question/show/knowledge/getTopics?pageIndex=1&knowledgeSelectType=0&knowledgeType=0&knowledgeId=" + coventlist(knowledgeid) + "&paperId=&level=0&gradeCode=" + gradecode + "&sectionCode=&difficultyCode=" + difficulty +
                                     "&paperTypeCode=&topicFromCode=&areas=&year=&sortField=default&sortDirection=true&keyWord=+&knowledgeTag=01&keywordSearchField=topic&excludePapers=&isRelatedPapers=true", data="phaseCode=05&subjectCode="+subjectscode, verify=isVerifysslCert, headers=editheaders, cookies=teacher.cookies)
    switch_tch(tchAccount, using_tch_session, u_tch_info)
    time.sleep(requestdelay/len(tchAccount))
    while firstget.status_code != 200:
        input("出错了：状态码：" + str(firstget.status_code), u_tch_info)
        # print(u_tch_info[1],u_tch_info[2])
        firstget = using_tch_session.get("https://www.zhixue.com/paperfresh/api/question/show/knowledge/getTopics?pageIndex=1&knowledgeSelectType=0&knowledgeType=0&knowledgeId=" + coventlist(knowledgeid) + "&paperId=&level=0&gradeCode=" + gradecode + "&sectionCode=&difficultyCode=" + difficulty +
                                         "&paperTypeCode=&topicFromCode=&areas=&year=&sortField=default&sortDirection=true&keyWord=+&knowledgeTag=01&keywordSearchField=topic&excludePapers=&isRelatedPapers=true", data="phaseCode=05&subjectCode="+subjectscode, verify=isVerifysslCert, headers=editheaders, cookies=teacher.cookies)
        switch_tch(tchAccount, using_tch_session, u_tch_info)
        time.sleep(requestdelay/len(tchAccount))
    firstget = json.loads(firstget.text)
    throwerror(firstget)
    htmltext = ""
    if firstget["result"]["pager"]:
        totalcount = int(firstget["result"]["pager"]["totalCount"])
        pages = int(totalcount / 10)
        if pages <= 1:
            if (totalcount <= counts):
                htmltext += arrangelist(firstget["result"]["pager"]["list"])
            else:
                templist = 0
                allquestions = firstget["result"]["pager"]["list"]
                realchoice = []
                while (templist < counts):
                    choice = random.randint(0, len(allquestions)-1)
                    realchoice.append(allquestions[choice])
                    templist += 1
                htmltext += arrangelist(realchoice)
        else:
            pagechoice = random.randint(1, pages)
            if pagechoice == 1:
                templist = 0
                allquestions = firstget["result"]["pager"]["list"]
                realchoice = []
                while (templist < counts):
                    choice = random.randint(0, len(allquestions)-1)
                    realchoice.append(allquestions[choice])
                    del allquestions[choice]
                    templist += 1
                htmltext += arrangelist(realchoice)
            else:
                secondget = using_tch_session.get("https://www.zhixue.com/paperfresh/api/question/show/knowledge/getTopics?pageIndex=" + str(pagechoice) + "&knowledgeSelectType=0&knowledgeType=0&knowledgeId=" + coventlist(knowledgeid) + "&paperId=&level=0&gradeCode=" + gradecode + "&sectionCode=&difficultyCode=" + difficulty +
                                                  "&paperTypeCode=&topicFromCode=&areas=&year=&sortField=default&sortDirection=true&keyWord=+&knowledgeTag=01&keywordSearchField=topic&excludePapers=&isRelatedPapers=true", data="phaseCode=05&subjectCode="+subjectscode, verify=isVerifysslCert, headers=editheaders, cookies=teacher.cookies)
                time.sleep(requestdelay/len(tchAccount))
                switch_tch(tchAccount, using_tch_session, u_tch_info)
                while secondget.status_code != 200:
                    input("出错了：状态码：" + str(secondget.status_code), u_tch_info)
                    secondget = using_tch_session.get("https://www.zhixue.com/paperfresh/api/question/show/knowledge/getTopics?pageIndex=1&knowledgeSelectType=0&knowledgeType=0&knowledgeId=" + coventlist(knowledgeid) + "&paperId=&level=0&gradeCode=" + gradecode + "&sectionCode=&difficultyCode=" + difficulty +
                                                      "&paperTypeCode=&topicFromCode=&areas=&year=&sortField=default&sortDirection=true&keyWord=+&knowledgeTag=01&keywordSearchField=topic&excludePapers=&isRelatedPapers=true", data="phaseCode=05&subjectCode="+subjectscode, verify=isVerifysslCert, headers=editheaders, cookies=teacher.cookies)
                    time.sleep(requestdelay/len(tchAccount))
                    switch_tch(tchAccount, using_tch_session, u_tch_info)
                secondget = json.loads(secondget.text)
                throwerror(secondget)
                templist = 0
                allquestions = secondget["result"]["pager"]["list"]
                realchoice = []
                while (templist < counts):
                    choice = random.randint(0, len(allquestions)-1)
                    realchoice.append(allquestions[choice])
                    del allquestions[choice]
                    templist += 1
                htmltext += arrangelist(realchoice)
    return htmltext


print("欢迎使用智学网错题生成助手")
global stuAccount
global tchAccount
global using_tch_session
using_tch_session = ""
stuAccount = []
print("本软件国内下载地址：https://gitee.com/w2016561536/zhixue_errorbook")
if config_stu_name != "" and config_stu_pwd != "":
    loginname = config_stu_name
    loginpwd = config_stu_pwd
    print("已从配置中读取学生用户名和密码")
else:
    loginname = input("请输入学生账户用户名：")
    loginpwd = input("请输入学生账户密码：")
loginrespond = loginwithpwd(loginname, loginpwd, 0, "")
student = loginrespond[0]
useruid = loginrespond[1]
username = loginrespond[2]
getstuinfo = student.get("https://www.zhixue.com/container/container/student/account/",
                         verify=isVerifysslCert, cookies=student.cookies, headers=editheaders)
getstuinfo = json.loads(getstuinfo.text)
cgrade = getstuinfo["student"]["clazz"]["grade"]["name"]
dgrage = getstuinfo["student"]["clazz"]["grade"]["code"]
print("年级：" + cgrade)
# stuAccount.append([loginrespond,loginname,loginpwd])
teacher = ""
hardcount = -2
easycount = -2
tchAccount = []
global u_tch_info
u_tch_info = ""
loginname = "a"
while loginname != "":
    loginname = input("请输入教师账户用户名，用于推题：")
    if loginname:
        loginpwd = input("请输入教师账户密码：")
        loginrespond = loginwithpwd(loginname, loginpwd, 0, "")
        teacher = loginrespond[0]
        tchrealname = loginrespond[2]
        tchAccount.append([teacher, loginname, loginpwd, tchrealname])
        easycount = -1
if easycount == -1:
    using_tch_session = tchAccount[0][0]
    u_tch_info = tchAccount[0]
requireSameType = False
headerforerrbook["XToken"] = "null"
xtoken = getxtoken(student)
headerforerrbook["XToken"] = xtoken
subjectdict = getsubject(student)
subjectcode = input("请输入待生成学科的id：")
while not subjectcode in subjectdict:
    print("别瞎输入")
    subjectcode = input("请输入待生成学科的id：")
if easycount == -1:
    easycount = input("所需同等难度推题数量[0,10]：")
    while easycount.isdigit() != True or easycount.find(".") != -1:
        easycount = input("所需同等难度推题数量[0,10]：")
    if easycount == "":
        easycount = 0
    elif int(easycount) > 10:
        easycount = 10
    elif int(easycount) < 0:
        easycount = 0
    else:
        easycount = int(easycount)

    hardcount = input("所需高难度推题数量[0,10]：")
    while hardcount.isdigit() != True or hardcount.find(".") != -1:
        hardcount = input("所需高难度推题数量[0,10]：")
    if hardcount == "":
        hardcount = 0
    elif int(hardcount) > 10:
        hardcount = 10
    elif int(hardcount) < 0:
        hardcount = 0
    else:
        hardcount = int(hardcount)

    requireSameType = input("是否需要按原题类型推题（是请随意输入后回车，否直接回车）：")
    if requireSameType == "":
        requireSameType = False
    else:
        requireSameType = True

startdateraw = input("请输入起始时间，格式为yyyy/mm/dd，无需补0：")
global starttimestamp
global endtimestamp
flage = True
global recoginzedtime
global endrecoginzedtime
while flage:
    try:
        recoginzedtime = datetime.datetime.strptime(startdateraw, "%Y/%m/%d")
    except:
        startdateraw = input("时间格式错误，请重新输入")
        continue
    else:
        secondcheck = input(
            "识别到的数据为:" + recoginzedtime.strftime("%Y-%m-%d") + "是否正确?\n正确请留空，错误请重新输入")
        if secondcheck == "":
            flage = False
            starttimestamp = str(int(recoginzedtime.timestamp()) * 1000)
        else:
            startdateraw = secondcheck
# 以下其实为终止时间，变量名不想改了
enddateraw = input("请输入终止时间，留空为现在：")
if enddateraw == "":
    endtimestamp = str(int(time.mktime(time.localtime())) * 1000)
    endrecoginzedtime = datetime.datetime.now()
else:
    flage = True
    while flage:
        try:
            endrecoginzedtime = datetime.datetime.strptime(
                enddateraw, "%Y/%m/%d")
        except:
            enddateraw = input("时间格式错误，请重新输入")
            continue
        else:
            secondcheck = input(
                "识别到的数据为:" + endrecoginzedtime.strftime("%Y-%m-%d") + "是否正确?\n正确请留空，错误请重新输入")
            if secondcheck == "":
                flage = False
                endtimestamp = str(int(endrecoginzedtime.timestamp()) * 1000)
            else:
                enddateraw = secondcheck
print("学科：" + subjectdict[subjectcode], "\n起始时间：", recoginzedtime.strftime(
    "%Y-%m-%d"), "\n终止时间：", endrecoginzedtime.strftime("%Y-%m-%d"))
print("正在获取数据")
htmltext = geterrorlists(student, subjectcode,
                         starttimestamp, endtimestamp, dgrage, hardcount, easycount, subjectdict[subjectcode], using_tch_session, requireSameType, tchAccount)
htmltext += "</body>"
htmltext += "<script>window.onload=function(){var c=document.getElementsByTagName(\"img\");for(var a=0,b;b=c[a];a++){if(b.width>630){b.width=630;}};var c=document.getElementsByTagName(\"table\");for(var a=0,b;b=c[a];a++){b.width=\"auto\"}};</script>\n"
htmltext += "<script type=\"text/javascript\" async \nsrc=\"https://static.zhixue.com/common/mathjax/2.7.1/MathJax.js?config=TeX-AMS_CHTML\" async></script>"
htmltext += "</html>"
htmltext = covent_img_to_latex(htmltext)
filepath = writefile(htmltext, username + "的" +
                     subjectdict[subjectcode] + "错题本" + str(time.mktime(time.localtime())) + ".html")
print("完成，保存在", filepath)
input("建议使用浏览器打开，使用CTRL+P键进行打印。\n按回车键退出程序")
