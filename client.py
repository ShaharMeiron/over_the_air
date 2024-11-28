from protocol import *
import socket
import os
from shared_file_utils import *


#  What will happen in real world scenario?
def get_connected_to_server_client_socket(addr=("127.0.0.1", 5000)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(addr)
    logging.info("client connected.")
    return sock


def input_function():
    logging.debug("receiving function")
    function_name = input("write the name of the function : ")
    code = ""
    while True:
        line = input("-")
        if line == "exit":
            break
        else:
            code += line + "\n"
    logging.debug("finished receiving function")
    return function_name, code


def input_arguments(function_name):
    if function_name == "add_function":
        # This part handles the 'add_function' case by asking for the function code
        logging.debug("Adding function requested.")
        return input_function()  # This will return function_name and code
    elif function_name == "upload":
        file_path = input("Enter the path of the file you want to upload\n--")
        return file_path, get_file_content(file_path)

    arguments_str: str = input("""Enter the arguments of the function you want to run in a JSON list format (e.g., ["arg1", "arg2"]). If there are no arguments, just hit Enter: \n""")

    if arguments_str.strip() == "":  # Handle empty input
        return []

    try:
        argument_list = json.loads(arguments_str)
        if not isinstance(argument_list, list):
            logging.error(f"Input is not a list: {arguments_str}")
            raise TypeError("Expected a JSON list.")
        return argument_list
    except Exception as e:
        logging.error(f"Failed to parse arguments: {e}")
        raise ValueError("Invalid input format. Please provide a valid JSON list.") from e


def verify_password(client_socket):
    logging.debug("verifying password...")
    for i in range(3):
        given_password = input("enter the password : ")
        msg_json = {"password": given_password}
        send_json(client_socket, msg_json)
        respond_json = recv_json(client_socket)
        print(respond_json["result"])
        if respond_json["status"] == "success":
            return True
    return False


def verify_email(client_socket):
    logging.debug("verifying email...")
    for i in range(3):
        email = input("Please enter your email : ")
        msg_json = {"email": email}
        send_json(client_socket, msg_json)
        respond_json = recv_json(client_socket)
        print(respond_json["result"])
        if respond_json["status"] == "success":
            return verify_password(client_socket)  # verifies the password that has been sent to the email
    return False


def verification_process(client_socket) -> bool:
    if verify_password(client_socket):
        if verify_email(client_socket):
            return True
    return False


def input_request_data():
    function_name = input("Enter the function you would like to run : ")
    function_arguments: list = input_arguments(function_name)
    return function_name, function_arguments


def send_request(client_socket, function_name, function_arguments):
    function_arguments_types: list = get_list_of_type_values(function_arguments)
    function_arguments = prepare_list_to_send(function_arguments)
    request: dict = {"function_name": function_name,
                     "function_arguments": function_arguments,
                     "arguments_types": function_arguments_types}
    return send_json(client_socket, request)


def receive_respond(client_socket):
    respond = recv_json(client_socket)
    output_values = respond["output_values"]
    function_arguments_types = respond["output_values_types"]
    logging.debug(f"function arguments types : {function_arguments_types}")
    output_values = return_list_to_original_values(output_values, function_arguments_types)
    return output_values


def save_files(output_values, file_counter, client_received_files_dir_path):
    # Ensure directory exists
    if not os.path.exists(client_received_files_dir_path):
        os.makedirs(client_received_files_dir_path)
        logging.debug(f"Created directory: {client_received_files_dir_path}")

    for val in output_values:
        if isinstance(val, bytes):
            try:
                # Identify file type
                file_type = identify_file_type_by_bytes(val)
                logging.debug(f"Identified file type: {file_type}")

                # Construct file path
                file_path = os.path.join(client_received_files_dir_path, f"{file_counter}.{file_type}")

                # Save file
                save_file(file_path, val)
                logging.info(f"File saved: {file_path}")

                # Increment counter
                file_counter += 1
            except Exception as e:
                logging.error(f"Failed to save file: {e}")
        else:
            logging.warning(f"Output value is not bytes, skipping: {val}")
    return file_counter



def main():
    while True:
        client_socket = get_connected_to_server_client_socket()
        # try:
        #     is_verified = verification_process(client_socket)
        # except Exception as e:
        #     client_socket.close()
        #     break
        # if not is_verified:
        #     client_socket.close()
        #     break

        file_counter = 0
        client_received_files_dir_path = "client_received_files"
        while True:
            logging.debug("receiving command")
            try:
                function_name, function_arguments = input_request_data()
                logging.debug(f"function name : {function_name}, function arguments : {function_arguments}")

                send_request(client_socket, function_name, function_arguments)

                output_values = receive_respond(client_socket)

                # saving bytes values to files, I am assuming byte values should be a file content in this case
                if output_values:
                    file_counter = save_files(output_values, file_counter, client_received_files_dir_path)
            except socket.error as e:
                logging.error(f"Connection error occurred :{e}")
                break
            except Exception as e:
                logging.error(f"Exception occurred : {e}")


if __name__ == '__main__':
    logging.basicConfig(filemode='w', filename="client.log", level=logging.DEBUG)
    main()
