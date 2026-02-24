# process_yaml.py file
import yaml

def parser(path,option):
    yml_file = open(path).read()
    yml_dict = yaml.load(yml_file, yaml.SafeLoader)
    opt = yml_dict[option]
    return opt