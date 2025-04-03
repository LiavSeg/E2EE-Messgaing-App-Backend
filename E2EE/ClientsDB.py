"""
ClientsDB class provides a thread-safe interface to interact with the e2ee.db SQLite database.
This class manages clients and messages data on a multithreaded server.
"""
import sqlite3
import constants
import datetime
import threading
from constants import DB_NAME


class ClientsDB:
    def __init__(self):
        """
            DefensiveDB class constructor
            Initializes a backup path for the files and a locking mechanism for thread safety
        """
        self.create_db()
        self.lock = threading.Lock()

    def create_db(self):
        """
            This function creates a new SQLite database named defensive.db [if it doesn't exist]
            The database contains two table - clients, files
            clients table contains: UUID field[primary key], Username string, public RSA key, last seen and AES key
            files table contains: UUID - primary key,file name, file path and verified (CRC)
        """
        try:
            connect_db = sqlite3.connect(DB_NAME)
            cursor = connect_db.cursor()
            build_messages_db_cmd = """CREATE TABLE IF NOT EXISTS messages(
                recipient_num INT,
                message_number INT,
                packet BLOB ,
                PRIMARY KEY (recipient_num, message_number)
            );
            """
            build_client_db_cmd = """CREATE TABLE IF NOT EXISTS clients(
                phone_num INT PRIMARY KEY,
                user_name TEXT,
                public_key BLOB,
                last_seen TEXT,
                 aes_key BLOB
            );
            """
            cursor.execute(build_messages_db_cmd)   # creates pending messages table for the db if not exists
            cursor.execute(build_client_db_cmd)  # creating clients table for the db if not exists
            connect_db.commit()
            connect_db.close()
        except Exception as e:
            self.db_error_handler(e)

    def thread_connect(self):
        """ returns a safe thread connection to the database"""
        try:
            return sqlite3.connect(DB_NAME, check_same_thread=False)
        except Exception as e:
            self.db_error_handler(e)

    def run_thread_query(self, query, params=(), fetch=False):
        """ This function wraps any database usage with the locking mechanism
            to enable reliable and safe multithreaded usage while using the 'critical section' of the server i.e. the db
            If the fetch flag is on (true) a data will be returned to the calling function, Otherwise no data is returned
        """
        with self.lock:
            connect = self.thread_connect()
            cursor = connect.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone() if fetch else cursor.rowcount
            connect.commit()
            connect.close()
            return result

    def update_entry(self, table_name: str, phone_num: bytes, field_name: str, field_data, file=False, filename=''):
        """ Updates a table field for a given user (phone_num) and a given table (files or clients) """
        try:
            update_query = f"UPDATE {table_name} SET {field_name} = ? WHERE phone_num = ?;"
            if file and filename:
                update_query = f"UPDATE {table_name} SET {field_name} = ? WHERE uuid = ? AND file_name = ?;"
                self.run_thread_query(update_query, (field_data, phone_num, filename), False)
            else:
                self.run_thread_query(update_query, (field_data, phone_num), False)
            if table_name == constants.CLIENTS_TABLE:
                last_seen_query = f"UPDATE {constants.CLIENTS_TABLE} SET {constants.LAST_SEEN_FIELD} = ? WHERE phone_num = ?;"
                self.run_thread_query(last_seen_query, (self.get_current_timedate(),phone_num), False)
        except Exception as e:
            self.db_error_handler(e, table_name)

    def get_data(self, table_name, uid, field_name):
        """"Gets data (field_name)  from a specific table(table_name) of a specific user(uid)  """
        try:
            select_query = f"SELECT {field_name} FROM {table_name} WHERE phone_num = ?;"
            data = self.run_thread_query(select_query, (uid,), True)
            if not data:
                raise ValueError(f'Could not locate {field_name} from {table_name} - can\'t proceed')
            return data[0]
        except Exception as e:
            self.db_error_handler(e, table_name)

    def find_username(self, phone_num):
        """
            This function finds if a given username is in the database
            If the user is in the database, it will return a list with uuid and REGISTRATION_FAIL code error
            If the user does not exist, it will return a list with empty binary string and INIT_REGISTRATION_SUCC
        """
        search = 'SELECT phone_num FROM clients WHERE phone_num = ?'
        exists = self.run_thread_query(search, (phone_num,), True)
        if exists is None:
            return False
        return True

    def add_new_client_db(self, uid: int, _name: str):
        try:
            insert_query = 'INSERT INTO clients (phone_num, user_name, public_key, last_seen, aes_key) VALUES (?, ?, ?, ?, ?);'
            self.run_thread_query(insert_query, (uid, _name, b'public_key', self.get_current_timedate(), b'aes_key'))
        except Exception as e:
            self.db_error_handler(e, 'clients')

    def get_current_timedate(self):
        """return the current time and date"""
        last_seen = datetime.datetime.now()
        return last_seen.strftime("%d-%m-%Y %H:%M:%S")

    def delete_queued_message(self, recipient_num, packet_num):
        """Deletes a file that its CRC could not be verified for three times"""
        try:
            delete_query = 'DELETE FROM messages WHERE recipient_num = ? AND message_number = ? '
            deleted = self.run_thread_query(delete_query, (recipient_num, packet_num))
            return True
        except Exception as e:
            self.db_error_handler(e)

    def get_queued_message(self, recipient_num):
        """gets a packet of an offline message for a client"""
        try:
            fetch_query = """SELECT packet, message_number FROM messages WHERE recipient_num = ? ORDER BY message_number ASC LIMIT 1"""
            packet_num = self.run_thread_query(fetch_query, (recipient_num,),True)
            return packet_num
        except Exception as e:
            self.db_error_handler(e)

    def insert_message(self,recipient_num, packet):
        try:
            msg_num = 'SELECT COALESCE(MAX(message_number), 1) FROM messages WHERE recipient_num = ?;'
            max_message_number = self.run_thread_query(msg_num, (recipient_num,), True)[0]
            new_message_number = max_message_number + 1
            insert_quarry = """
                INSERT INTO messages (recipient_num, message_number, packet)
                VALUES (?, ?, ?);"""
            insert = self.run_thread_query(insert_quarry, (recipient_num, new_message_number, packet))
        except Exception as e:
            self.db_error_handler(e)

    def count_values(self, recipient_num):
        check_query = """
            SELECT COUNT(*) 
            FROM messages 
            WHERE recipient_num = ?;
        """
        return self.run_thread_query(check_query, (recipient_num,),True)[0]

    def db_error_handler(self,e, table_name=''):
        if isinstance(e, sqlite3.IntegrityError):
            raise Exception(f'in db {table_name} data inserted may violate constraints {e}')
        if isinstance(e, sqlite3.ProgrammingError):
            raise Exception(f'invalid SQL operation {e}')
        if isinstance(e, sqlite3.OperationalError):
            raise Exception(f'failed to create database {e}')
        if isinstance(e, Exception):
            raise Exception(f'SQLite DB related error occurred {e}')