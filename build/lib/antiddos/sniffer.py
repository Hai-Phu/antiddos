import argparse
from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class
from .features.loader import Loader

def job():
    print("I'm working...")

def create_sniffer(
    input_file, input_interface, output_file=None
):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(output_file)

    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )


def main():
    parser = argparse.ArgumentParser()
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )

    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )

    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-c",
        "--csv",
        "--flow",
        action="store",
        dest="output_file",
        help="output flows as csv",
    )

    args = parser.parse_args()

    sniffer = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_file,
    )
    sniffer.start()
    # loader = Loader("Loading with object...", "Done", 0.05).start()

    try:
        sniffer.join()
        
    except KeyboardInterrupt:
        sniffer.stop()
        # loader.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    main()
