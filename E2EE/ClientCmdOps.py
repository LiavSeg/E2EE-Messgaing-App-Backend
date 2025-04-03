"""
This module handles client's interactive interaction with the application
"""

from Client import Client
SEPARATION = '-----------------------------------\n'
CONNECTED_PROMPT ='Application Functions Menu:\n\tTo send a message for another client press: M\n\tTo disconnect press: D\n\tTo wait for new messages press: W\n\tresponse: '
PHONE_NUM = 'Enter client\'s phone number: '


def client_operation():
    try:
        client = init_client()
        if signup_or_register(client):
            start_connected_client(client)

    except Exception as e:
        print(e)


def init_client():
    """Creates a new client with the user's input"""
    print('#######################\nWelcome to best E2EE app!\n')
    user_id = get_valid_phone()
    client = Client(user_id)
    return client

def signup_or_register(client):
    ops = {
        'r'.upper(): register,
        's'.upper(): signup
    }
    is_registered = input('Signup or reconnect? S\\R ').upper()
    while is_registered not in ops:
        print('invalid choice, please enter S for signing up or R to reconnect ')
        is_registered = input('Signup or reconnect? S\\R ').upper()
        print('\n')

    operation = ops[is_registered]
    return operation(client)
def register(client):
    print('Registering as a new client... Please wait for the OTP')
    return client.create_new_account()

def signup(client):
    print('Signing up ... Please wait for a confirmation')
    return client.reconnect()
    print('#######################\n')
    
def start_connected_client(client):
    connected = True
    ops = {
        'M': message,
        'D': disconnect,
        'W': wait_for_messages
    }
    while connected:
        operation_prompt = input(SEPARATION+CONNECTED_PROMPT).upper()
        while operation_prompt not in ops:
            operation_prompt = input(SEPARATION+CONNECTED_PROMPT)
        print(SEPARATION)
        operation = ops[operation_prompt]
        connected = operation(client)

def message(client):
    recipient = get_valid_phone(string=True)
    client.send_msg_client_to_client(recipient.encode('utf-8'))
    return True
def disconnect(client):
    client.client_disconnect()
    return False

def wait_for_messages(client):
    print('Waiting for new messages...')
    client.response_handler.handle_server_response()
    return True

def get_valid_phone(string=False):
    phone = input(PHONE_NUM)
    while len(phone) != 9 or not phone.isdigit():
        print('Invalid choice, phone number contain digits only and in total length of 9')
        phone = input(PHONE_NUM)
    return int(phone) if not string else phone
