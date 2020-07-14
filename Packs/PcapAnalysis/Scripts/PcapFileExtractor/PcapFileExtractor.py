import hashlib
import subprocess
import tempfile
from enum import Enum
from typing import List, Optional, Set, Tuple, Union

import magic
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

import demistomock as demisto


class InclusiveExclusive(Enum):
    INCLUSIVE: str = 'inclusive'
    EXCLUSIVE: str = 'exclusive'


def get_file_path_from_id(entry_id: str) -> Tuple[str, str]:
    """

    Args:
        entry_id: ID of the file from context.

    Returns:
        file path, name of file
    """
    file_obj = demisto.getFilePath(entry_id)
    return file_obj.get('path'), file_obj.get('name')


def run_command(args: list, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    """Running a process

    Args:
        args: args as will be passed to Popen
        stdout: STDOUT pipe
        stderr: STDERR pipe

    Raises:
        DemistoException if returncode is different than 0
    """
    process = subprocess.Popen(args, stdout=stdout, stderr=stderr)
    stdout_data, stderr_data = process.communicate()
    if process.returncode != 0:
        raise DemistoException(f'Error returned from tshark command: {process.returncode}\n {stderr_data!r}')


def filter_files(
        root: str, files: List[str],
        types: Optional[Set[str]] = None,
        extensions: Optional[Set[str]] = None,
        types_inclusive_or_exclusive: Optional[str] = None,
        extensions_inclusive_or_exclusive: Optional[str] = None
) -> List[str]:
    """Filtering files by its MIME type and file extension.

    Args:
        root: file's root
        files: files to filter
        types: types to filter by.
        extensions: extensions to filter by.
        types_inclusive_or_exclusive: should types set be inclusive or exclusive
        extensions_inclusive_or_exclusive: should extensions set be inclusive or exclusive

    Returns:
        Filtered file list.
    """
    magic_mime = magic.Magic(mime=True)
    for file in files:
        # types list supplied,
        if types:
            mime_type = magic_mime.from_file(os.path.join(root, file))
            # Inclusive types, take only the types in the list.
            if types_inclusive_or_exclusive == InclusiveExclusive.INCLUSIVE and mime_type not in types:
                files.remove(file)
            # Exclusive types, don't take those files.
            elif types_inclusive_or_exclusive == InclusiveExclusive.EXCLUSIVE and mime_type in types:
                files.remove(file)
        if extensions:
            # strip `.` from extension
            extensions = set([extension.split('.')[-1] for extension in extensions])
            # Get file extension without a leading point.
            f_ext = os.path.splitext(file)[1].split('.')[-1]
            # Inclusive extensions, take only the types in the list.
            if extensions_inclusive_or_exclusive == InclusiveExclusive.INCLUSIVE and f_ext not in extensions:
                files.remove(file)
            # Exclude extensions, don't take those files.
            elif extensions_inclusive_or_exclusive == InclusiveExclusive.EXCLUSIVE and f_ext in extensions:
                files.remove(file)
    return files


def upload_files(
        file_path: str, dir_path: str,
        types: Optional[Set[str]] = None, extensions: Optional[Set[str]] = None,
        types_inclusive_or_exclusive: Optional[str] = None,
        extensions_inclusive_or_exclusive: Optional[str] = None,
        wpa_pwd: Optional[str] = None,
        rsa_path: Optional[str] = None,
        limit: int = 5
) -> Union[CommandResults, str]:
    """Extracts files and delivers it to CortexSOAR

    Args:
        file_path: the path to the PCAP file
        dir_path: dir path for the files
        types: types to filter by.
        extensions: extensions to filter by.
        types_inclusive_or_exclusive: should types set be inclusive or exclusive
        extensions_inclusive_or_exclusive: should extensions set be inclusive or exclusive
        wpa_pwd: password to the file (if WPA-PWD protected)
        rsa_path: path to a private key file (if TLS encrypted)
        limit: maximum files to extract (default 5)

    Returns:
        Extracted files to download

    """
    command = ['tshark', '-r', f'{file_path}', '--export-objects', f'http,{dir_path}',
               '--export-objects', f'smb,{dir_path}', '--export-objects', f'imf,{dir_path}',
               '--export-objects', f'tftp,{dir_path}', '--export-objects', f'dicom,{dir_path}']
    # If WPA-PWD protected
    if wpa_pwd:
        command.extend([
            '-o', 'wlan.enable_decryption:TRUE',
            '-o', f'uat:80211_keys:"wpa-pwd","{wpa_pwd}"'
        ])
    # If need to decrypt the file using a RSA key
    if rsa_path:
        command.extend(['-o', f'uat:rsa_keys:"{rsa_path}",""'])

    run_command(command)

    context = []
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    for root, _, files in os.walk(dir_path):
        # Limit the files list to the limit provided by the user
        files = files[: limit]
        if not files:
            return 'No files found.'
        # Filter files
        files = filter_files(root, files,
                             types=types,
                             extensions=extensions,
                             extensions_inclusive_or_exclusive=extensions_inclusive_or_exclusive,
                             types_inclusive_or_exclusive=types_inclusive_or_exclusive)
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.join(file)

            with open(file_path, 'rb') as file_stream:
                data = file_stream.read()
                demisto.results(fileResult(file_name, data))

                md5.update(data)
                sha1.update(data)
                sha256.update(data)

            context.append({
                'FileMD5': md5.hexdigest(),
                'FileSHA1': sha1.hexdigest(),
                'FileSHA256': sha256.hexdigest(),
                'FileName': file_name,
                'FileSize': os.path.getsize(file_path),
                'FileExtension': os.path.splitext(file_name)[1]
            })

        readable_output = tableToMarkdown('Pcap Extracted Files', [{'name': file_name} for file_name in files])

        results = CommandResults(
            outputs_prefix='PcapExtractedFiles',
            outputs_key_field='FileMD5',
            outputs=context,
            readable_output=readable_output
        )
        return results
    return 'No files found in path.'


def main(
        entry_id: str,
        wpa_password: Optional[str] = None,
        rsa_decrypt_key_entry_id: Optional[str] = None,
        types: Optional[str] = None,
        types_inclusive_or_exclusive: Optional[str] = 'inclusive',
        extensions: Optional[str] = None,
        extensions_inclusive_or_exclusive: str = 'inclusive',
        limit: str = '5',
):
    with tempfile.TemporaryDirectory() as dir_path:
        try:
            file_path, file_name = get_file_path_from_id(entry_id)
            cert_path, _ = get_file_path_from_id(rsa_decrypt_key_entry_id) if rsa_decrypt_key_entry_id else (None, None)
            return_results(upload_files(
                file_path, dir_path,
                types=set(argToList(types)),
                extensions=set(argToList(extensions)),
                types_inclusive_or_exclusive=types_inclusive_or_exclusive,
                extensions_inclusive_or_exclusive=extensions_inclusive_or_exclusive,
                wpa_pwd=wpa_password,
                rsa_path=cert_path,
                limit=int(limit) if limit else 5
            ))
        except Exception as e:
            return_error(f'Failed to execute PcapFileExtractor. Error: {str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main(**demisto.args())
