"""Command-line argument parser."""
import argparse


def get_parse():
    parser = argparse.ArgumentParser(
        description='Ingram-Pro: Network camera vulnerability scanner (enhanced)'
    )
    parser.add_argument('-i', '--in_file',  type=str, required=True,
                        help='File containing target IP addresses (one per line)')
    parser.add_argument('-o', '--out_dir',  type=str, required=True,
                        help='Directory to save results')
    parser.add_argument('-p', '--ports',    type=int, nargs='+', default=None,
                        help='Port(s) to scan (overrides defaults)')
    parser.add_argument('-t', '--th_num',   type=int, default=150,
                        help='Concurrency level (default: 150)')
    parser.add_argument('-T', '--timeout',  type=int, default=3,
                        help='Request timeout in seconds (default: 3)')
    parser.add_argument('-D', '--disable_snapshot', action='store_true',
                        help='Disable snapshot capture')
    parser.add_argument('--no-resume', dest='no_resume', action='store_true',
                        help='Ignore previous scan state and start fresh')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    return parser.parse_args()
