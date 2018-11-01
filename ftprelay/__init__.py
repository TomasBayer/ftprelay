import logging
import os

from pyftpdlib.authorizers import AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logger = logging.getLogger(__name__)


class AuthenticationFailedError(Exception):
    pass


class FTPRelay(FTPServer):

    def __init__(self, address, file_processor_creator):
        self.file_processor_creator = file_processor_creator
        super().__init__(address, self.build_handler())

    def build_handler(self):
        class CustomAuthorizer(object):
            file_processor_creator = self.file_processor_creator

            def __init__(self):
                self.file_processors = {}

            def get_home_dir(self, username):
                home_dir = '/dev/shm/{}/{}/'.format(__name__, username)
                os.makedirs(home_dir, exist_ok=True)
                return home_dir

            def has_perm(self, username, perm, path=None):
                return perm == 'w'

            def get_msg_login(self, username):
                return "Hello."

            def get_msg_quit(self, username):
                del self.file_processors[username]
                return "Goodbye."

            def impersonate_user(self, username, password):
                pass

            def terminate_impersonation(self, username):
                pass

            def validate_authentication(self, username, password, handler):
                try:
                    self.file_processors[username] = self.file_processor_creator(username, password)
                except AuthenticationFailedError as err:
                    raise AuthenticationFailed() from err

        class CustomHandler(FTPHandler):
            authorizer = CustomAuthorizer()

            # Process received file routine
            def on_file_received(self, filename):
                logger.info('Received file {}'.format(os.path.basename(filename)))

                # Upload file
                self.authorizer.file_processors[self.username](filename)

                # Remove file
                os.remove(filename)

        return CustomHandler
