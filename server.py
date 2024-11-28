import hashlib
import socket
from protocol import *
from client_runnable_functions import *
import random
import smtplib
from email.mime.text import MIMEText


def get_server_socket(addr: tuple) -> socket.socket:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(addr)
    server_sock.listen()
    return server_sock


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


def first_password_verification(client_socket, password) -> bool:
    logging.debug("verifying password...")
    for i in range(3):
        json_data = recv_json(client_socket)
        given_password = json_data["password"]
        if hashlib.sha256(given_password.encode()).hexdigest() == password:
            result = "password is correct."
            respond_json = {"status": "success", "result": result}
            send_json(client_socket, respond_json)
            return True
        result = f"password incorrect you have {2 - i} tries left"
        respond_json = {"status": "failure", "result": result}
        send_json(client_socket, respond_json)
    return False


def email_password_verification(client_socket, password):
    for i in range(3):
        json_data = recv_json(client_socket)
        given_password = json_data["password"]
        if given_password == password:
            json_respond = {"result": "password is correct", "status": "success"}
            send_json(client_socket, json_respond)
            return True
        else:
            json_respond = {"result": "password is incorrect", "status": "failure"}
            send_json(client_socket, json_respond)
    return False


def email_password(email: str, password: str):
    sender_email = email
    app_password = "zzyt aopw jsro cblh"
    subject = "Your Verification Code"
    body = f"Your verification code is: {password}"
    message = MIMEText(body, "plain")
    message["From"] = email
    message["To"] = email
    message["Subject"] = subject

    try:
        # Connect to Gmail SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade connection to secure
            server.login(sender_email, app_password)
            server.sendmail(sender_email, email, message.as_string())
        print("Email sent successfully!")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        raise e


def email_verification(client_socket):
    verified_emails = ["shaharmeiron@gmail.com"]
    for i in range(3):
        json_data = recv_json(client_socket)
        email = json_data["email"]
        if email in verified_emails:
            result = "we have emailed you a password to verify its you"
            status = "success"
            respond_json = {"result": result, "status": status}
            send_json(client_socket, respond_json)
            password = str(random.randint(0, 1000000)).zfill(6)
            email_password(email, password)
            return email_password_verification(client_socket, password)
        else:
            result = f"email isn't verified you have {2 - i} tries left"
            status = "failure"
            respond_json = {"result": result, "status": status}
            send_json(client_socket, respond_json)
        return False


def is_client_verified(client_socket):
    if first_password_verification(client_socket,password="b493d48364afe44d11c0165cf470a4164d1e2609911ef998be868d46ade3de4e") and email_verification(client_socket):
        return True
    client_socket.close()
    return False


def main(server_address):
    server_socket = get_server_socket(server_address)
    while True:
        logging.info("waiting for a client to connect")
        client_socket, address = server_socket.accept()

        # client verification
        # try:
        #     if not is_client_verified(client_socket):
        #         break
        # except socket.error as e:
        #     client_socket.close()
        #     logging.error(f"socket error occurred : {e}")
        # except Exception as e:
        #     logging.error(f"Exception occurred while verifying client : {e}")

        logging.info(f"client connection from : {address} have been verified")
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
    main((ip, port))

