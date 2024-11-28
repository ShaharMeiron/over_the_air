import base64
import json
import logging
import magic


def recv_by_size(sock, size: int) -> bytes:

    data = b""
    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by the peer")
            data += chunk
        except Exception as e:
            logging.error(f"Error occurred while receiving data : {e}")
            raise e
    return data


def recv_until(sock, delimiter=b"\r\n") -> str:
    data = b""
    while not data.endswith(delimiter):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed by the peer")
        data += chunk
    return data.decode('utf-8')


def prepare_list_to_send(values_to_send):  # converts bytes to string with base64
    logging.debug("preparing list values to be sent successfully")
    for index in range(len(values_to_send)):
        if isinstance(values_to_send[index], bytes):
            logging.debug("bytes object detected in the values that are about to be sent")
            values_to_send[index] = bytes_to_b64str(values_to_send[index])
    return values_to_send


def return_list_to_original_values(values_to_convert, types):
    logging.debug("returning list to original values")
    number_of_list_values = len(values_to_convert)
    for i in range(number_of_list_values):
        if types[i] == "<class 'bytes'>":
            logging.debug("base64 string detected in the list,will be converted back to bytes")
            values_to_convert[i] = b64str_to_bytes(values_to_convert[i])
    return values_to_convert


def receive_header(receiving_socket) -> str:
        logging.debug("Receiving header")
        header = recv_until(receiving_socket, delimiter=b"\r\n")
        logging.debug(f"Header received: {header}")
        return header


def recv_json(s) -> dict:  # receives a dictionary
    length = int(receive_header(s))
    logging.debug("receiving json data...")
    try:
        json_data = json.loads(recv_by_size(s, length).decode())
        if not isinstance(json_data, dict):  # validation
            raise TypeError("received values are not in a dict")
        logging.debug(f"received json data : {json_data}")
        return json_data
    except Exception as e:
        logging.error(f"Exception occurred while receiving data : {e}")
        raise e


def get_list_of_type_values(values) -> list:  # returns a list of the values types
    types = []
    for val in values:
        types.append(str(type(val)))
    return types


def send_json(sending_socket, message_data: dict) -> bool:
    try:
        logging.debug(f"sending json data to the other side")
        json_data = json.dumps(message_data).encode()
        length = str(len(json_data)).encode()
        data = length + b"\r\n" + json_data
        logging.debug(f"sending data : {data}")
        sending_socket.sendall(data)
        return True
    except Exception as e:
        logging.error(f"Exception occurred while sending json data : {e}")
        return False


def bytes_to_b64str(bytes_val: bytes):
    return base64.b64encode(bytes_val).decode()


def b64str_to_bytes(string: str):
    return base64.b64decode(string.encode())


def return_type_strings_to_type_objects(str_types: list[str]) -> list:
    original_types: list[type] = []
    for str_type in str_types:  # type string = str(type) = "<class 'type'>"
        original_type: type = eval(str_type[str_type.find("'"):-1])
        if not isinstance(original_type, type):
            raise TypeError(f"This string was not a type : {str_type}")
        original_types.append(original_type)
    return original_types
