import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from pyftpdlib.authorizers import AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logger = logging.getLogger(__name__)

DEFAULT_BASE_PATH = Path('/dev/shm/ftprelay')


class AuthenticationFailedError(Exception):
    pass


class FileProcessor(ABC):

    @abstractmethod
    def process_file(self, file: Path) -> None:
        raise NotImplementedError()


class Authenticator(ABC):

    @abstractmethod
    def authenticate(self, username: str, password: str) -> FileProcessor:
        raise NotImplementedError()


@dataclass
class CustomAuthorizer:
    authenticator: Authenticator
    tmp_dir_base_path: Path

    file_processors: dict[str, FileProcessor] = field(init=False, default_factory=dict)

    def get_home_dir(self, username: str) -> str:
        path = self.tmp_dir_base_path / username
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    def has_perm(self, username: str, perm: str, path=None) -> bool:
        return perm == 'w'

    def get_msg_login(self, username: str) -> str:
        return 'Hello.'

    def get_msg_quit(self, username: str) -> str:
        del self.file_processors[username]
        return 'Goodbye.'

    def impersonate_user(self, username: str, password: str):
        pass

    def terminate_impersonation(self, username: str):
        pass

    def validate_authentication(self, username: str, password: str, handler: FTPHandler):
        try:
            self.file_processors[username] = self.authenticator.authenticate(username, password)
        except AuthenticationFailedError as err:
            raise AuthenticationFailed() from err


@dataclass
class FTPRelay:
    authenticator: Authenticator
    tmp_dir_base_path: Path = DEFAULT_BASE_PATH
    host: str = '127.0.0.1'
    port: int = 21

    ftp_server: FTPServer = field(init=False)

    def __post_init__(self):
        class CustomHandler(FTPHandler):
            authorizer = CustomAuthorizer(self.authenticator, self.tmp_dir_base_path)

            # Process received file routine
            def on_file_received(self, filename: str):
                path = Path(filename)

                logger.info(f"Received file {path.name}")

                # Upload file
                self.authorizer.file_processors[self.username].process_file(path)

                # Remove file
                path.unlink()

        self.ftp_server = FTPServer(address_or_socket=(self.host, self.port), handler=CustomHandler)

    def start(self):
        self.ftp_server.serve_forever()

    def stop(self):
        self.ftp_server.close_all()
