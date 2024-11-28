import os
import importlib
from PIL import ImageGrab
import pyperclip
from shared_file_utils import *


def list_functions():
    protected_keys: list = []
    for key in original_functions_to_run.keys():
        protected_keys.append(key)
    client_added_keys: list = []
    for key in client_added_functions.keys():
        client_added_keys.append(key)
    keys_dict = {"original server functions": protected_keys, "client added functions": client_added_keys}

    return keys_dict


def import_module(module_name):
    try:
        # Dynamically import the module and make it available globally

        module = importlib.import_module(module_name)
        globals()[module_name] = module
        print(f"Module '{module_name}' imported successfully.")
        return module
    except ModuleNotFoundError:
        print(f"Module '{module_name}' not found.")
    except Exception as e:
        print(f"An error occurred while importing '{module_name}': {e}")


def list_directory_files(dir_path=None) -> list:
    if dir_path is None:
        dir_path = os.getcwd()
    return os.listdir(dir_path)


def download(file_path: str) -> bytes:
    return get_file_content(file_path)


def upload(file_path: str, content: bytes):
    try:
        save_file(file_path, content)
        return True
    except Exception as e:
        logging.error(f"Exception occurred while saving a file : {e}")
        return False


def get_screenshot(path=r"server_screenshot.png") -> bytes:  # returns image bytes
    screenshot = ImageGrab.grab()
    screenshot.save(path)
    screenshot.close()
    with open(path, 'rb') as image:
        return image.read()


def paste(s: str):
    pyperclip.copy(s)


def copy() -> str:
    return pyperclip.paste()


def check_function(func_str):
    func_code = compile(func_str, "no source", "exec")
    pass


import ast


def is_code_allowed(func_code: str) -> bool:  # checks if a code contains only one function and don't have syntax error
    try:
        tree = ast.parse(func_code)
    except SyntaxError:
        return False

    top_level_nodes = tree.body
    if len(top_level_nodes) != 1:
        return False

    return isinstance(top_level_nodes[0], ast.FunctionDef)


def add_function(func_name: str, func_code: str) -> (bool, str):
    if not is_code_allowed(func_code):
        logging.debug("code is not allowed")
        raise Exception("code might have invalid syntax or isn't a single function")
    try:
        exec(func_code, client_added_functions)
        print(f"Function '{func_name}' added successfully.")
    except Exception as e:
        logging.error(f"Error adding function '{func_name}': {e}")
        result = str(e)
        return False, result
    result = "success"
    return True, result


def remove_function(func_name):
    client_added_functions.pop(func_name)


client_added_functions = {}


original_functions_to_run = {
    "add_function": add_function,
    "get_screenshot": get_screenshot,
    "upload": upload,
    "download": download,
    "import_module": import_module,
    "list_directory_files": list_directory_files,
    "paste": paste,
    "copy": copy,
    "list_functions": list_functions,
    "remove_function": remove_function
}

