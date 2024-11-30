from protocol import *
import socket
import os
from shared_file_utils import *
import ssl


#  What will happen in real world scenario?
def get_connected_to_server_client_socket(addr, certfile=r"C:\Users\Shahar\Downloads\rootCA.pem",
                      keyfile=r"C:\Users\Shahar\Downloads\rootCA.key"):
    """
    Create an SSL/TLS client socket and connect to the server.

    Args:
        addr (tuple): A tuple of (host, port) to connect to.
        certfile (str): Path to the client's certificate file.
        keyfile (str): Path to the client's private key file.

    Returns:
        ssl.SSLSocket: The SSL-wrapped client socket.
    """
    # Create an SSL context for client
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False  # For debugging, disables hostname validation
    context.verify_mode = ssl.CERT_NONE  # For debugging, disables server certificate validation

    # Load client certificate and key (for mutual authentication if required)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # Create a raw socket and wrap it with SSL
    sock = socket.create_connection(addr)
    encrypted_socket = context.wrap_socket(sock, server_hostname=addr[0])
    return encrypted_socket


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


def main(addr):
    while True:
        client_socket = get_connected_to_server_client_socket(addr)
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
    ip = "127.0.0.1"
    port = "5000"
    logging.info("client program have started...")
    server_addr = (ip, port)
    main(server_addr)
    logging.info("client program have ended")
