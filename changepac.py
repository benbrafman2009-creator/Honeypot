import pydivert
with pydivert.Divert("tcp.DstPort == 5000") as diverter:
    for packet in diverter:
        print(f"Captured: {packet}")
        diverter.send(packet)  # Re-inject the packet back into the stack