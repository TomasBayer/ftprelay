# ftprelay

`ftprelay` is a lightweight Python module that provides a simple framework for setting up a minimal, non-persisting FTP server whose single purpose is to execute custom code on uploaded files before discarding them.

It was developed with the goal of retrofitting older devices or software that exclusively support FTP upload for file transfer, enabling a broader range of applications.

## Quick Navigation

- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [License](#license)

## Installation

Install `ftprelay` using pip:

```bash
pip install ftprelay
```

## Usage

1. Implement the `process_file()` method in a custom class that inherits from `FileProcessor`. This method defines how
   uploaded files should be processed.
2. Implement the `authenticate()` method in a custom class that inherits from `Authenticator`. This method should either
   raise an `AuthenticationFailedError` or, upon successful authentication, return an instance of the custom `FileProcessor` that dictates how the file should be processed for this user.
3. Instantiate and start FTPRelay:

```python
    relay = FTPRelay(authenticator=MyCustomAuthenticator(), host='127.0.0.1', port=21)
relay.start()
```

This initializes an FTP server, where logins are authenticated using your custom Authenticator. Upon successful
authentication, uploaded files are temporarily stored. The storage path of each file is then passed to the associated
FileProcessor class returned by the Authenticator. Finally, the files are promptly deleted after processing.

### Caveats

- Any other operation other than file upload is denied by the FTP server with a 550 error code.
- There are no subfolders on the FTP server, nor does it allow the creation of any. Thus, all files must be directly
  uploaded to the root directory.
- Using interactive FTP browsers to access the server may result in errors, as they are restricted from reading the
  contents of the root directory.

## Example

A basic example for a FTP relay that sends the uploaded files via email to a recipient address depending on the user.

```python
from dataclasses import dataclass
from pathlib import Path

from ftprelay import AuthenticationFailedError, Authenticator, FileProcessor, FTPRelay


@dataclass
class CustomFileProcessor(FileProcessor):
    recipient_email: str

    def process_file(self, path: Path) -> None:
        # Placeholder code: send email with attachment
        send_email(to=self.recipient_email, attachment=path)


class CustomAuthenticator(Authenticator):

    def authenticate(self, username: str, password: str) -> FileProcessor:
        # Placeholder code: verify credentials
        if verify(username, password):
            return CustomFileProcessor(recipient_email=f"{username}@example.org")
        else:
            raise AuthenticationFailedError()

# Instantiate and start the FTPRelay
relay = FTPRelay(authenticator=CustomAuthenticator(), host='127.0.0.1', port=21)
relay.start()
```

## License

`ftprelay` is distributed under the terms of the MIT License.
