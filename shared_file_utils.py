import logging
import magic


def save_file(file_path: str, file_content: bytes):
    try:
        logging.debug(f"saving image at : {file_path}")
        file = open(file_path, 'wb')
        file.write(file_content)
        file.close()
    except Exception as e:
        logging.error(f"couldn't save image as expected : {e} ")
        raise e


def get_file_content(file_path) -> bytes:
    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except Exception as e:
        logging.error(f" couldn't get file content : {e}")


def identify_file_type_by_bytes(file_bytes):  # returns the type of file by its magic bytes
    try:
        magic_obj = magic.Magic(mime=False)
        file_type = magic_obj.from_buffer(file_bytes)
        return file_type[:file_type.find(" ")].lower()
    except Exception as e:
        logging.error(f"Error occurred while identifying file type : {e}")
