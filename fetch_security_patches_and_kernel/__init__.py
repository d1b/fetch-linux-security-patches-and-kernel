#!/usr/bin/python
from __future__ import print_function

import lzma
import os
import re
import tempfile

import requests
from requests_futures.sessions import FuturesSession


def get_associated_kernel_version(grsec_download_url):
    version = grsec_download_url.split('/')[-1].split('-')[0].strip('v')
    return version


def get_latest_unofficial_grsec_patch_and_sig_url():
    download_url = None
    sig_download_url = None
    url = ('https://api.github.com/repos/minipli/'
           'linux-unofficial_grsec/releases/latest')
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    for asset in data['assets']:
        name = asset['name']
        browser_url = asset['browser_download_url']
        if 'unofficial_grsec' not in name:
            continue
        if name.endswith('.diff'):
            download_url = browser_url
        elif name.endswith('.diff.sig'):
            sig_download_url = browser_url
    return download_url, sig_download_url


def get_latest_linux_hardened_patch_and_sig_url(patch_name):
    repo = 'copperhead'
    if patch_name == 'linux-hardened-anthraxx':
        repo = 'anthraxx'
    url = ('https://api.github.com/repos/%s/'
           'linux-hardened/releases/latest' % repo)
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    for asset in data['assets']:
        name = asset['name']
        browser_url = asset['browser_download_url']
        if name.endswith('.patch'):
            download_url = browser_url
        elif name.endswith('.patch.sig'):
            sig_download_url = browser_url
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


def download_linux_hardened(patch_name):
    download_url, sig_download_url = (
        get_latest_linux_hardened_patch_and_sig_url(patch_name))
    kernel_version = re.match(
        r'linux\-hardened\-(?P<ver>[\d\.\d]+)\..*',
        download_url.split('/')[-1]
    ).group('ver')
    _download(download_url, sig_download_url, kernel_version)


def download_grsec():
    download_url, sig_download_url = (
        get_latest_unofficial_grsec_patch_and_sig_url())
    kernel_version = get_associated_kernel_version(download_url)
    _download(download_url, sig_download_url, kernel_version)


def _download(download_url, sig_download_url, kernel_version):
    k_download_url, k_sig_download_url = get_kernel_download_and_sig_url(
        kernel_version)
    dl_directory = tempfile.mkdtemp(prefix='linux-security-download')
    print('Downloading patch (%s) and kernel files to %s' % (
        download_url.split('/')[-1], dl_directory))
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
