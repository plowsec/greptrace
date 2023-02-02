from lxml import etree
import sys
import logging
from dataclasses import dataclass
import os
logging.basicConfig(level=logging.DEBUG)

@dataclass
class Endpoint:
    class_name: str
    url: str
    fully_qualified_name: str

    def __str__(self):
        return f"URL={self.url} class name = {self.class_name} fqdn = {self.fully_qualified_name}"


@dataclass
class Bean:

    group = ""
    class_name=""
    action="" # *.do
    method="" # method name in the related class
    url = "/"

    def __str__(self):

        return f"URL = {self.url} code @ {self.class_name}.{self.method} (group = {self.group} action={self.action})"

    def __repr__(self):
        return self.__str__()

def get_beans_config_path(path_to_xml):

    endpoints = [] # Endpoint instances
    restricted = []
    servlets = {} # servlet[name] = class_name...

    tree = etree.parse(path_to_xml)

    # Remove namespace prefixes
    for elem in tree.getiterator():
        if not(type(elem) == etree._Comment):
            elem.tag = etree.QName(elem).localname

    # Remove unused namespace declarations
    etree.cleanup_namespaces(tree)
    beans_found = False

    for url in tree.xpath("/web-app/context-param"):


        for child in list(url):

            if child.tag == "param-name":
                if child.text == "bean-factory":
                    #logging.info("Beans Factory found")
                    beans_found = True
            if child.tag == "param-value" and beans_found:
                beans_path = child.text
                #logging.info(f"beans_path = {beans_path}")
                return beans_path.split(", ")


def parse_mvc_action_config(file):

    tree = etree.parse(file)

    # Remove namespace prefixes
    for elem in tree.getiterator():
        if not(type(elem) == etree._Comment):
            elem.tag = etree.QName(elem).localname

    # Remove unused namespace declarations
    etree.cleanup_namespaces(tree)
    beans_found = False
    beans = []
    for url in tree.xpath("/mvc-action-config/action-set"):

        if "bean" in url.attrib.keys():
            bean = url.attrib["bean"]
        elif "class" in url.attrib.keys():
            bean = url.attrib["class"]

        for child in list(url):

            if child.tag == "action":
                name = child.attrib["name"]
                if "execute" in child.attrib.keys():
                    method = child.attrib["execute"]
                elif "validate" in child.attrib.keys():
                    method = child.attrib["validate"]
                elif "authorize" in child.attrib.keys():
                    method = child.attrib["authorize"]

                #logging.info(f"Found bean {bean} with action = {name} and method = {method}")
                new_bean = Bean()
                new_bean.group = bean
                new_bean.action = name
                new_bean.method = method
                beans += [new_bean]
    return beans


# enrich a "beans" collection with class information
def parse_beans_file(file):

    tree = etree.parse(file)

    # Remove namespace prefixes
    for elem in tree.getiterator():
        if not(type(elem) == etree._Comment):
            elem.tag = etree.QName(elem).localname

    # Remove unused namespace declarations
    etree.cleanup_namespaces(tree)
    beans_found = False

    beans_info = {} # id:class
    for url in tree.xpath("/beans/bean"):

        # not so sure about this
        if not "id" in url.attrib.keys() or not "class" in url.attrib.keys():
            continue

        #logging.info(url.attrib["class"])
        beans_info[url.attrib["id"]] = url.attrib["class"]

    return beans_info

def file_contains(file, pattern):
    with open(file) as fl:
        res = next((l for l in fl if pattern in l), None)

    return res

def parse_beans(path_to_xml):

    beans_path = get_beans_config_path(path_to_xml) + ["mvcactions.xml"]

    basepath = os.path.dirname(path_to_xml)
    all_beans = {} # id(group):class
    beans_file = ""
    parsed_mvc_actions = False
    for file in beans_path:
        abspath_actionsbeans = os.path.join(basepath, os.path.basename(file))
        #logging.info(abspath_actionsbeans)

        if file_contains(abspath_actionsbeans, "mvc-action-config"):
            beans = parse_mvc_action_config(abspath_actionsbeans)
            parsed_mvc_actions = True
        if file_contains(abspath_actionsbeans, "<beans "):
            all_beans.update(parse_beans_file(abspath_actionsbeans))

    # enrich with the "class" information
    if parsed_mvc_actions:

        for bean in beans:

            if bean.group in all_beans.keys():
                bean.class_name = all_beans[bean.group]

    # enrich with the complete URL
    for bean in beans:
        for file in beans_path:
            abspath_actionsbeans = os.path.join(basepath, os.path.basename(file))
            with open(abspath_actionsbeans) as f:
                for line in f:

                    if bean.action in line:
                        bean.url = "/"+"/".join(line.split("/")[1:]).split("\"")[0]
                        #logging.info("Found URL: " + bean.url)
                        break
                else:
                    break

    logging.info("Beans: ")
    for bean in beans:
        logging.info(bean)

    return beans

def parse(path_to_xml):

    endpoints = [] # Endpoint instances
    restricted = []
    servlets = {} # servlet[name] = class_name...

    tree = etree.parse(path_to_xml)

    # Remove namespace prefixes
    for elem in tree.getiterator():
        if not(type(elem) == etree._Comment):
            elem.tag = etree.QName(elem).localname

    # Remove unused namespace declarations
    etree.cleanup_namespaces(tree)
    for url in tree.xpath("/web-app/servlet-mapping"):

        new_endpoint = ""
        new_url = ""

        for child in list(url):

            if child.tag == "servlet-name":
                new_endpoint = child.text
                continue

            if child.tag == "url-pattern":
                new_url = child.text

        endpoints += [Endpoint(new_endpoint, new_url, "")]

    # collect endpoints that are restricted to a given role
    for url in tree.xpath("/web-app/security-constraint/web-resource-collection/url-pattern"):
        restricted += [url.text]

    # remove them from the initial list
    unauth_endpoints = filter(lambda x: x.url not in restricted, endpoints)

    # collect the fully qualified class names
    for element in tree.xpath("/web-app/servlet"):

        servlet_class = ""
        servlet_name = ""

        for child in element:

            if child.tag == "servlet-class":
                servlet_class = child.text
                continue

            if child.tag == "servlet-name":
                servlet_name = child.text

        servlets[servlet_name] = servlet_class


    # update the remaining Endpoints with their fully qualified class name
    for endpoint in endpoints:

        if servlets.get(endpoint.class_name):
            endpoint.fully_qualified_name = servlets[endpoint.class_name].strip()


    logging.info(f"Filtered {len(endpoints) - len(restricted)} results")

    logging.info("All endpoints:")
    for endpoint in endpoints:
        logging.info(endpoint)

    logging.info("Unauthenticated endpoints:")
    for endpoint in unauth_endpoints:
        logging.info(endpoint)

    return unauth_endpoints, endpoints

if __name__ == '__main__':

    if len(sys.argv) < 2:
        logging.info("Usage: path to web.xml")
        exit(-1)

    parse(sys.argv[1])
    parse_beans(sys.argv[1])
