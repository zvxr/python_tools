
import ftplib
import os


class FTPClient(object):
    """Class to wrap ftplib.FTP. The with statement may be used for managing
    connecting/disconnecting from client. The client attribute may also be
    accessed directly, and closed manually with the close method.

    Example usage:
    ```
    ftpclient = FTPClient('ftp.debian.org')
    with ftpclient as client:
        client.cwd('debian')
        client.retrlines('LIST')
    ```
    """
    BLOCK_SIZE = 1024  # For storing in binary mode.
    DEFAULT_TIMEOUT = 30  # 30 seconds.

    def __init__(
        self,
        host,
        user="anonymous",
        passwd="anonymous@",
        timeout=DEFAULT_TIMEOUT
    ):
        self.host = host
        self.user = user
        self.passwd = passwd
        self.timeout = timeout
        self.logger = logger
        self._client = None

    def __enter__(self):
        return self.client

    def __exit__(self, type, value, tb):
        self.close()

    @property
    def client(self):
        if not self._client:
            self._client = ftplib.FTP(**self.get_connection_params())

        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def get_connection_params(self):
        params = {'host': self.host}
        if self.user:
            params['user'] = self.user
        if self.passwd:
            params['passwd'] = self.passwd
        if self.timeout:
            params['timeout'] = self.timeout
        return params


def download_file(ftp_client, file_path, dest_path=None, ascii_mode=True):
    """Downloads a file from remote FTP server.
    `ftp_client`: an FTPClient instance.
    `file_path`: a string representing file location on remote server.
    `dest_path`: a string representing file destination on local server.
    Defaults to the current directory with a file name matching the remote file.
    `ascii_mode`: Boolean. When True downloads using ASCII mode. False uploads
    using Binary mode.
    """
    # Determine remote file directory and name.
    file_dir, file_name = file_path.rpartition('/')[::2]

    # Make sure destination directory exists. Determine the destination.
    if dest_path is not None:
        dest_dir = dest_path.rpartition('/')[0]
        if dest_dir and not os.path.exists(dest_dir):
            raise IOError("Local directory does not exist: {0}".format(dest_dir))
    else:
        dest_path = file_name

    with ftp_client as client:
        if file_dir:
            client.cwd(file_dir)

        if ascii_mode:
            client.retrlines("RETR {0}".format(file_name), open(dest_path))
        else:
            client.retrbinary(
                "RETR {0}".format(file_name),
                open(dest_path, "wb").write,
                FTPClient.BLOCK_SIZE
            )


def upload_file(ftp_client, file_path, dest_path=None, ascii_mode=True):
    """Uploads a file to remote FTP server.
    `ftp_client`: an FTPClient instance.
    `file_path`: a string representing file location, locally.
    `dest_path`: a string representing file destination on remote server.
    Defaults to the top level of the server with a file name matching the local
    file.
    `ascii_mode`: Boolean. When True uploads using ASCII mode. False uploads
    using Binary mode.
    """
    # Make sure the file exists.
    if not os.path.isfile(file_path):
        raise IOError("File does not exist: {0}".format(file_path))

    # Determine the destination directory and file name.
    if dest_path:
        dest_dir, dest_file_name = dest_path.rpartition('/')[::2]
    else:
        dest_dir = None
        dest_file_name = file_path.split('/')[-1]

    with ftp_client as client:
        if dest_dir:
            client.cwd(dest_dir)

        if ascii_mode:
            client.storlines("STOR {0}".format(dest_file_name), open(file_path))
        else:
            client.storbinary(
                "STOR {0}".format(dest_file_name),
                open(file_path, "rb"),
                FTPClient.BLOCK_SIZE
            )
