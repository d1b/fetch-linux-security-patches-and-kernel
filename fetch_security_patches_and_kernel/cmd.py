import argparse

from . import (
    download_grsec,
    download_linux_hardened,
)


def main():
    parser = argparse.ArgumentParser(
        description='Fetch a linux security kernel patch')
    choices = ['unofficial-grsec', 'linux-hardened', 'linux-hardened-anthraxx']
    parser.add_argument(
        '-p',
        '--patch',
        choices=choices,
        default=choices[-1],
        help='The patch type to download(default: %(default)s)',
        dest='patch')
    args = parser.parse_args()
    if args.patch == choices[0]:
        download_grsec()
    else:
        download_linux_hardened(args.patch)


if __name__ == '__main__':
    main()
