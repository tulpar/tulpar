# -*- coding: utf-8 -*-
import requests
import subprocess
import socket
import datetime
def cyberThreatIntelligence(baglanti,dosyaAdi):
    try:
        baglanti=socket.gethostbyaddr(baglanti)[2][0]
    except:
        pass
    response=requests.get('https://www.usom.gov.tr/url-list.txt',verify=False)
    icerik=response.content
    dosya = open(dosyaAdi, "a")
    bugun=datetime.datetime.today()
    yazi="[+]This report contains: "+str(baglanti)+"\nDate: "+str(bugun).split(" ")[0]+"\n=========\n"
    dosya.write(yazi)
    dosya.close()
    for i in str(icerik).split("\n"):
        if baglanti in i:
            print "This web site is harmful"
            dosya=open(dosyaAdi,"a")
            dosya.write("Usom: This web site is harmful..\n")
            dosya.close()
    url="https://virustotal.com/tr/domain/"+str(baglanti)+"/information/"

    response=requests.get(url)
    print "Virus total:",response.content
    ServerNameBasla=str(response.content).find("Server Name")
    ServerNameSon=str(response.content).find("</textarea>")
    dosya=open(dosyaAdi,"a")
    dosya.write(response.content[ServerNameBasla:ServerNameSon])
    dosya.close()
    print "Sonuc:",response.content[ServerNameBasla:ServerNameSon]
    print "Sonuc:",response.content[ServerNameBasla:ServerNameSon]
    sorgu="https://www.badips.com/get/info/"+str(baglanti)
    response=requests.get(sorgu,verify=False)
    #print response.json()['Listed']
    try:
        if response.json()['Listed'] == False:
            badips=response.json()['suc']+"\n"
            dosya=open(dosyaAdi,"a")
            dosya.write(badips)
            dosya.close()
        else:
            icerik=response.json()
            print icerik
            ListStatusBadIPs="Bad IP : "+icerik['suc']+"\n"
            CountryBadIPs = "Country: "+icerik['CountryCode'] + "\n"
            #InetnumBadIPs = "IP araligi: "+icerik['Whois']['inetnum'] + "\n"
            #DescrBadIPs = "Bilgi:"+icerik['Whois']['descr'][0] + "\n" + icerik['Whois']['descr'][1] +"\n"
            ReportCountIPs = "Report number: "+str(icerik['ReporterCount']['sum']) +"\n"
            CategoryBadIPs = "Category: " +icerik['Categories'][0]+"\n"
            #badips=ListStatusBadIPs + CountryBadIPs + InetnumBadIPs + DescrBadIPs + ReportCountIPs + CategoryBadIPs
            badips = ListStatusBadIPs + CountryBadIPs  + ReportCountIPs + CategoryBadIPs
            dosya=open(dosyaAdi,"a")
            dosya.write(badips)
            dosya.close()
    except:
        print "Information not available..."
    BlockListSSH=requests.get('https://lists.blocklist.de/lists/ssh.txt',verify=False)
    print "BlockListSSH"
    print BlockListSSH.content
    print "============"
    if baglanti in str(BlockListSSH.content):
        BlockListSSHBilgi=str(baglanti)+" ,the last 48 hour have been reported on the blocklist for an attack on the SSH service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListSSHBilgi)
        dosya.close()
    else:
        BlockListSSHBilgi=str(baglanti)+" ,the last 48 hour haven't been reported on the blocklist for an attack on the SSH service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListSSHBilgi)
        dosya.close()
    BlockListMail=requests.get('https://lists.blocklist.de/lists/mail.txt',verify=False)
    print "BlockListMail"
    print BlockListMail.content
    print "============"
    if baglanti in str(BlockListMail.content):
        BlockListMailBilgi=str(baglanti)+" the last 48 hour have been reported on the blocklist for an attack on the mail service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListMailBilgi)
        dosya.close()
    else:
        BlockListMailBilgi=str(baglanti)+" the last 48 hour haven't been reported on the blocklist for an attack on the mail service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListMailBilgi)
        dosya.close()
    BlockListApache=requests.get('https://lists.blocklist.de/lists/apache.txt',verify=False)
    print "BlockListApache"
    print BlockListApache.content
    print "============"
    if baglanti in str(BlockListApache.content):
        BlockListApacheBilgi=str(baglanti)+" the last 48 hour have been reported on the blocklist for an attack on the apache service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListApacheBilgi)
        dosya.close()
    else:
        BlockListApacheBilgi=str(baglanti)+" the last 48 hour haven't been reported on the blocklist for an attack on the apache service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListApacheBilgi)
        dosya.close()
    BlockListImap=requests.get('https://lists.blocklist.de/lists/imap.txt',verify=False)
    print "BlockListImap"
    print BlockListImap.content
    print "============"
    if baglanti in str(BlockListImap.content):
        BlockListImapBilgi=str(baglanti)+" the last 48 hour have been reported on the blocklist for an attack on the IMAP and POP3 service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListImapBilgi)
        dosya.close()
    else:
        BlockListImapBilgi=str(baglanti)+" the last 48 hour haven't been reported on the blocklist for an attack on the IMAP and POP3 service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListImapBilgi)
        dosya.close()
    BlockListFtp=requests.get('https://lists.blocklist.de/lists/ftp.txt',verify=False)
    print "BlockListFtp"
    print BlockListFtp.content
    print "============"
    if baglanti in str(BlockListFtp.content):
        BlockListFtpBilgi=str(baglanti)+" the last 48 hour have been reported on the blocklist for an attack on the FTP service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListFtpBilgi)
        dosya.close()
    else:
        BlockListFtpBilgi=str(baglanti)+" the last 48 hour have been reported on the blocklist for an attack on the FTP service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListFtpBilgi)
        dosya.close()
    BlockListSip=requests.get('https://lists.blocklist.de/lists/sip.txt',verify=False)
    print "BlockListSip"
    print BlockListSip.content
    print "============"
    if baglanti in str(BlockListSip.content):
        BlockListSipBilgi=str(baglanti)+"  have been reported on the blocklist for an attack on the SIP, VOIP service.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListSipBilgi)
        dosya.close()
    else:
        BlockListSipBilgi=str(baglanti)+"  haven't been reported on the blocklist for an attack on the SIP, VOIP service\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListSipBilgi)
        dosya.close()
    BlockListBots=requests.get('https://lists.blocklist.de/lists/bots.txt',verify=False)
    print "BlockListBots"
    print BlockListBots.content
    print "============"
    if baglanti in str(BlockListBots.content):
        BlockListBotsBilgi=str(baglanti)+" the last 48 hour have been reported on the blocklist for RFI-Attacks, REG-Bots, IRC-Bots, BadBot attack.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListBotsBilgi)
        dosya.close()
    else:
        BlockListBotsBilgi=str(baglanti)+" the last 48 hour haven't been reported on the blocklist for RFI-Attacks, REG-Bots, IRC-Bots, BadBot attack.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListBotsBilgi)
        dosya.close()
    BlockListIRC=requests.get('https://lists.blocklist.de/lists/ircbot.txt',verify=False)
    print "BlockListIRC"
    print BlockListIRC.content
    print "============"
    if baglanti in str(BlockListIRC.content):
        BlockListIRCBilgi=str(baglanti)+" have been reported on the blocklist for IRC Bot.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListIRCBilgi)
        dosya.close()
    else:
        BlockListIRCBilgi=str(baglanti)+" haven't been reported on the blocklist for IRC Bot.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListIRCBilgi)
        dosya.close()
    BlockListBruteForceLogin=requests.get('https://lists.blocklist.de/lists/bruteforcelogin.txt',verify=False)
    print "BlockListBruteForceLogin"
    print BlockListBruteForceLogin.content
    print "============"
    if baglanti in str(BlockListBruteForceLogin.content):
        BlockListBruteForceLoginBilgi=str(baglanti)+" have been reported on the blocklist for using easy entry in Joomla,Wordpress.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListBruteForceLoginBilgi)
        dosya.close()
    else:
        BlockListBruteForceLoginBilgi=str(baglanti)+" haven't been reported on the blocklist for using easy entry in Joomla,Wordpress.\\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BlockListBruteForceLoginBilgi)
        dosya.close()
    EmergingThreatBlockIP=requests.get('http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',verify=False)
    print "EmergingThreatBlockIP"
    print EmergingThreatBlockIP.content
    print "============"
    if baglanti in str(EmergingThreatBlockIP.content):
        EmergingThreatBlockIPBilgi=str(baglanti)+"  have been reported on the Emerging Threat Block IP.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(EmergingThreatBlockIPBilgi)
        dosya.close()
    else:
        EmergingThreatBlockIPBilgi=str(baglanti)+"  haven't been reported on the Emerging Threat Block IP.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(EmergingThreatBlockIPBilgi)
        dosya.close()
    EmergingThreatComromisedIP=requests.get('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',verify=False)
    print "EmergingThreatComromisedIP"
    print EmergingThreatComromisedIP.content
    print "============"
    if baglanti in str(EmergingThreatComromisedIP.content):
        EmergingThreatComromisedIPBilgi=str(baglanti)+"  have been reported on the Emerging Threat.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(EmergingThreatBlockIPBilgi)
        dosya.close()
    else:
        EmergingThreatComromisedIPBilgi=str(baglanti)+"  haven't been reported on the Emerging Threat.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(EmergingThreatBlockIPBilgi)
        dosya.close()
    BinaryDefenceBanList=requests.get('http://www.binarydefense.com/banlist.txt',verify=False)
    print "BinaryDefenceBanList"
    print BinaryDefenceBanList.content
    print "============"
    if baglanti in str(BinaryDefenceBanList.content):
        BinaryDefenceBanListBilgi=str(baglanti)+"  have been reported on the Binary Defence.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BinaryDefenceBanListBilgi)
        dosya.close()
    else:
        BinaryDefenceBanListBilgi=str(baglanti)+"  haven't been reported on the Binary Defence.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(BinaryDefenceBanListBilgi)
        dosya.close()
    Openphish=requests.get('https://openphish.com/feed.txt',verify=False)
    print "Openphish"
    print Openphish.content
    print "============"
    if baglanti in str(Openphish.content):
        OpenphishBilgi=str(baglanti)+"  have been reported on the Openphish.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(OpenphishBilgi)
        dosya.close()
    else:
        OpenphishBilgi=str(baglanti)+"  haven't been reported on the Openphish.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(OpenphishBilgi)
        dosya.close()
    ZeusBadIP=requests.get('https://zeustracker.abuse.ch/blocklist.php?download=badips',verify=False)
    print "ZeusBadIP"
    print ZeusBadIP.content
    print "============"
    if baglanti in str(ZeusBadIP.content):
        ZeusBadIPBilgi=str(baglanti)+"  have been reported on the Zeustracker.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(ZeusBadIPBilgi)
        dosya.close()
    else:
        ZeusBadIPBilgi=str(baglanti)+"  haven't been reported on the Zeustracker.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(ZeusBadIPBilgi)
        dosya.close()
    ProjectHoneypotTurkiye=requests.get('https://www.projecthoneypot.org/list_of_ips.php?by=3&ctry=TR',verify=False)
    if baglanti in ProjectHoneypotTurkiye.content:
        ProjectHoneypotTurkiyeBilgi=str(baglanti)+"  have been reported on the Honeypot Project.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(ProjectHoneypotTurkiyeBilgi)
        dosya.close()
    else:
        ProjectHoneypotTurkiyeBilgi=str(baglanti)+"  haven't been reported on the Honeypot Project.\n"
        dosya=open(dosyaAdi,"a")
        dosya.write(ProjectHoneypotTurkiyeBilgi)
        dosya.close()
