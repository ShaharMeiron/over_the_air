import socket
from protocol import *
from client_runnable_functions import *
import ssl


def get_server_socket(server_addr, certfile=r"certificate.pem", keyfile=r"private_key.key"):
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # Create and configure the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(server_addr)
    sock.listen(5)
    print(f"Server listening on {server_addr}")

    # Wrap the socket with SSL and return
    return context.wrap_socket(sock, server_side=True)


#  returns the output of the function in a list
def run_function(func_name: str, func_arguments: list) -> list:
    logging.debug(f"running function: {func_name} with given arguments : {func_arguments}")
    if func_name in original_functions_to_run.keys():
        func = original_functions_to_run[func_name]
    else:
        if func_name in client_added_functions.keys():
            func = client_added_functions[func_name]
        else:
            raise KeyError("function does not exist")
    output_values = [func(*func_arguments)]
    logging.debug(f"function output values : {output_values}")
    return output_values


def receive_request(client_socket):
    request_json: dict = recv_json(client_socket)
    function_name: str = request_json["function_name"]
    function_arguments = request_json["function_arguments"]
    arguments_types = request_json["arguments_types"]
    function_arguments = return_list_to_original_values(function_arguments, arguments_types)
    return function_name, function_arguments


def send_respond(client_socket, output_values):
    types = get_list_of_type_values(output_values)
    output_values = prepare_list_to_send(output_values)  # transforms bytes values to str with base64
    respond_json = {"output_values": output_values, "output_values_types": types}
    send_json(client_socket, respond_json)




def main(server_address):
    server_socket = get_server_socket(server_address)
    while True:
        logging.info("waiting for a client to connect")
        client_socket, client_address = server_socket.accept()

        logging.info(f"client connection from : {client_address} have been verified")
        while True:

            try:
                function_name, function_arguments = receive_request(client_socket)
                output_values = run_function(function_name, function_arguments)
                send_respond(client_socket, output_values)
            except socket.error as e:
                client_socket.close()
                logging.error(f"socket error occurred : {e}")
                break
            except Exception as e:
                logging.exception(e)
                respond_json = {"exception": str(e)}
                if not send_json(client_socket, respond_json):
                    client_socket.close()
                    break


if __name__ == '__main__':
    logging.basicConfig(filename="server.log", filemode='w', level=logging.DEBUG)
    ip = "127.0.0.1"
    port = 5000
    address = ("127.0.0.1", 5000)
    main((ip, port))


