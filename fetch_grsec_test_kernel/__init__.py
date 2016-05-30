#!/usr/bin/python
from __future__ import print_function

import lzma
import os
import requests
import tempfile
from defusedxml import ElementTree
from requests_futures.sessions import FuturesSession


def get_associated_kernel_version(grsec_download_url):
    return grsec_download_url.split('/')[-1].split('-')[2]


def get_latest_grsec_test_patch_and_sig_url():
    response = requests.get('https://grsecurity.net/testing_rss.php')
    doc = ElementTree.fromstring(response.content)
    download_url = doc.findall('.//guid')[-1].text
    sig_download_url = download_url + '.sig'
    return download_url, sig_download_url


def get_kernel_download_and_sig_url(kernel_version):
    return (
        'https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-%s.tar.xz' %
        kernel_version,
        'https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-%s.tar.sign' %
        kernel_version
    )


def get_safe_filename(url):
    file_part = url.split('/')[-1]
    name = os.path.basename(file_part[:255])
    if os.sep in name or (os.altsep and os.altsep in name):
        raise ValueError('Invalid filename %s' % name)
    return name


def extract_lzma_file(full_lzma_file_path, extract_to=None):
    if extract_to is None:
        extract_to = full_lzma_file_path[:-len('.xz')]
    print('Exacting %s to %s' % (full_lzma_file_path, extract_to))
    l_file = lzma.LZMAFile(full_lzma_file_path, mode='rb')
    with open(extract_to, 'wb') as f:
        while True:
            data = l_file.read(4096)
            if not data:
                break
            f.write(data)
    l_file.close()


def main():
    download_url, sig_download_url = get_latest_grsec_test_patch_and_sig_url()
    kernel_version = get_associated_kernel_version(download_url)
    k_download_url, k_sig_download_url = get_kernel_download_and_sig_url(
        kernel_version)
    dl_directory = tempfile.mkdtemp(prefix='grsec-download')
    print('Downloading grsec and kernel files to %s' % dl_directory)
    async_session = FuturesSession(max_workers=4)
    futures = []
    for url in [download_url, sig_download_url,
                k_download_url, k_sig_download_url]:
        safe_filename = get_safe_filename(url)
        futures.append((safe_filename, async_session.get(url)))
    for safe_filename, future in futures:
        result = future.result()
        try:
            result.raise_for_status()
            full_f_path = os.path.join(dl_directory, safe_filename)
            with open(full_f_path, 'wb+') as f:
                f.write(result.content)
            if safe_filename.endswith('.xz'):
                extract_lzma_file(full_f_path)
        except Exception as e:
            print('downloading %s failed %s' % (safe_filename, e))

